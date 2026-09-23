"""Throwaway containers for the test suite: MySQL, and an S3 store.

Pared down from `spyglass/tests/container.py`. The broker needs far less than
Spyglass does — no per-pipeline grants, no populated data directory, no
alternate MySQL versions — so what remains is: start a container, wait for it
to be ready, hand back credentials, and remove it afterwards.

Containers are named `broker-*`, so everything this project starts is
identifiable at a glance and removable with one filter. A repeat run reuses
the container already up rather than starting a second; CI gets a fresh runner
each time and so always starts new.

Pass `--container-vol-dir` to keep container data off the root disk. MySQL
wants a two gigabyte InnoDB log before it will start, and Docker's default
volume root is usually on `/`, which on a workstation is the disk with no room
to spare. Volumes are cleared whenever a container is removed, so a dropped
container never leaves a stale data directory behind.

The S3 sidecar is MinIO, chosen for a single-container start rather than
because the deployment will use it. That is the point of an S3-only adapter:
Ceph RGW, SeaweedFS, and Garage are all reachable by changing an endpoint, and
testing against any one of them tests the interface rather than the product.
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from pathlib import Path

MYSQL_NAME = "broker-pytest-db"
MYSQL_IMAGE = "datajoint/mysql:8.0"  # a minor line, not a moving latest
MYSQL_PASSWORD = "tutorial"
MYSQL_USER = "root"

S3_NAME = "broker-pytest-s3"
# quay.io, not Docker Hub: MinIO withdrew their images from Docker Hub, so
# `minio/minio` now refuses anonymous pulls. A developer with an old copy
# cached sees tests pass while CI cannot pull at all.
#
# Pinned to a release rather than `latest` for the same reason the move caught
# us: a moving tag lets an upstream change break CI with no commit here. Bump
# it deliberately.
S3_IMAGE = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z"
S3_USER = "spyglasstest"
S3_PASSWORD = "spyglasstestsecret"  # MinIO requires at least 8 characters
S3_BUCKET = "spyglass-store-test"


class _Container:
    """Shared lifecycle for a single-container service."""

    image = ""
    internal_port = 0
    #: Path inside the container whose contents are worth keeping off `/`.
    data_dir = ""

    def __init__(
        self, name: str, keep: bool = False, vol_dir: str | None = None
    ):
        """Start nothing yet; resolve identity, port, and storage.

        Parameters
        ----------
        name : str
            Container name, also the seed for the host port.
        keep : bool, optional
            Leave the container running on exit. Useful when iterating; the
            next run reuses it rather than paying startup again.
        vol_dir : str, optional
            Parent directory for this container's data, bind-mounted as
            `<vol_dir>/<name>`. Without it Docker stores volumes on its own
            root disk, which on a workstation is usually the one with no room
            to spare — MySQL alone wants a two gigabyte log before it starts.
        """
        import docker

        self.docker = docker
        self.client = docker.from_env()
        self.name = name
        self.keep = keep
        self.port = self._resolve_port()
        self.vol_dir = self._resolve_vol_dir(vol_dir)

    def _resolve_vol_dir(self, vol_dir: str | None) -> Path | None:
        """Return the host directory to bind, or None to let Docker decide."""
        if not vol_dir or not self.data_dir:
            return None

        # The name seeds a path, so strip anything that could nest a directory
        # or climb out of the parent.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", self.name).strip(".") or "_"

        return Path(vol_dir).expanduser().absolute() / safe

    def _existing(self):
        """Return the container with our name, or None."""
        try:
            return self.client.containers.get(self.name)
        except self.docker.errors.NotFound:
            return None

    def _resolve_port(self) -> int | None:
        """Return the port of a running container, or None to let Docker pick.

        Choosing a port ourselves means binding it, closing it, and starting a
        container some moments later — a gap in which a concurrent test
        session can take it. This repository expects concurrent sessions, and
        the collision presents as a confusing connection error rather than as
        a clash. Docker allocates atomically, so it should.
        """
        container = self._existing()

        if container is not None:
            bindings = container.attrs["NetworkSettings"]["Ports"]
            bound = bindings.get(f"{self.internal_port}/tcp")
            if bound:
                return int(bound[0]["HostPort"])

        return None

    def run_kwargs(self) -> dict:
        """Return image-specific arguments for `containers.run`."""
        raise NotImplementedError

    def start(self) -> None:
        """Start the container, reusing or restarting one if it exists."""
        container = self._existing()

        if container is None:
            volumes = None
            if self.vol_dir is not None:
                self.vol_dir.mkdir(parents=True, exist_ok=True)
                volumes = {
                    str(self.vol_dir): {"bind": self.data_dir, "mode": "rw"}
                }

            created = self.client.containers.run(
                image=self.image,
                name=self.name,
                ports={self.internal_port: self.port},
                detach=True,
                volumes=volumes,
                **self.run_kwargs(),
            )
            created.reload()
            bound = created.attrs["NetworkSettings"]["Ports"]
            self.port = int(bound[f"{self.internal_port}/tcp"][0]["HostPort"])
            return

        container.reload()

        if container.status == "exited":
            # Recreate rather than restart. A container that exited may have
            # died partway through first-time initialization, and MySQL in
            # particular refuses to initialize into a data directory that
            # already has files — so restarting wedges it permanently. These
            # are throwaway, so losing the volume costs nothing.
            self._remove(container)
            self.start()

    def ready(self) -> bool:
        """Return True when the service can serve requests."""
        raise NotImplementedError

    def wait(self, timeout: int = 180, interval: int = 2) -> None:
        """Block until `ready`, or raise.

        Failing loudly beats letting every test fail on connection refused.

        Raises
        ------
        RuntimeError
            If the service is not ready within `timeout`.
        """
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if self.ready():
                return
            time.sleep(interval)

        raise RuntimeError(
            f"Container {self.name} was not ready in {timeout}s. "
            f"Check `docker logs {self.name}`."
        )

    def stop(self) -> None:
        """Stop and remove the container, unless `keep` was set."""
        if self.keep:
            return

        container = self._existing()

        if container is None:
            return

        container.reload()
        if container.status != "exited":
            container.stop()
        self._remove(container)

    def _remove(self, container) -> None:
        """Remove a container and clear the data directory it was using.

        A bind mount outlives its container. Removing one without clearing the
        other points the next run at a half-written data directory, which
        MySQL refuses to initialize into — wedging it for good.
        """
        container.remove()

        if self.vol_dir is None or not self.vol_dir.exists():
            return

        try:
            # Through a container, because the files belong to the service's
            # uid and are not ours to delete from the host.
            self.client.containers.run(
                image="alpine:3",  # pinned; `latest` is a moving target
                command=["sh", "-c", "rm -rf /data/..?* /data/.[!.]* /data/*"],
                volumes={str(self.vol_dir): {"bind": "/data", "mode": "rw"}},
                remove=True,
                detach=False,
            )
            self.vol_dir.rmdir()
        except Exception:  # best effort; a stale dir must not fail a run
            pass


class MySQLContainer(_Container):
    """A MySQL server for DataJoint."""

    image = MYSQL_IMAGE
    internal_port = 3306

    data_dir = "/var/lib/mysql"

    def __init__(
        self, name: str = MYSQL_NAME, keep: bool = False, vol_dir=None
    ):
        super().__init__(name, keep, vol_dir)

    def run_kwargs(self) -> dict:
        """Root password and storage engine, as DataJoint expects."""
        return {
            "environment": [
                f"MYSQL_ROOT_PASSWORD={MYSQL_PASSWORD}",
                "MYSQL_DEFAULT_STORAGE_ENGINE=InnoDB",
            ],
            "tty": True,
        }

    def ready(self) -> bool:
        """The image ships a healthcheck; trust it."""
        container = self._existing()

        if container is None:
            return False

        container.reload()

        return container.health == "healthy"

    @property
    def credentials(self) -> dict:
        """DataJoint config for this container."""
        return {
            "database.host": "127.0.0.1",
            "database.user": MYSQL_USER,
            "database.password": MYSQL_PASSWORD,
            "database.port": self.port,
            "safemode": False,
        }


class S3Container(_Container):
    """A MinIO server, standing in for the deployed object store."""

    image = S3_IMAGE
    internal_port = 9000

    data_dir = "/data"

    def __init__(self, name: str = S3_NAME, keep: bool = False, vol_dir=None):
        super().__init__(name, keep, vol_dir)

    def run_kwargs(self) -> dict:
        """Serve `/data` with root credentials from the environment."""
        return {
            "command": "server /data",
            "environment": [
                f"MINIO_ROOT_USER={S3_USER}",
                f"MINIO_ROOT_PASSWORD={S3_PASSWORD}",
            ],
        }

    @property
    def endpoint_url(self) -> str:
        """Where boto3 should point."""
        return f"http://127.0.0.1:{self.port}"

    def ready(self) -> bool:
        """Poll MinIO's liveness endpoint.

        The image carries no Docker healthcheck, so readiness is asked over
        HTTP rather than read off the container.
        """
        try:
            with urllib.request.urlopen(
                f"{self.endpoint_url}/minio/health/live", timeout=2
            ) as response:
                return response.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def settings_kwargs(self) -> dict:
        """Return `Settings` fields pointing at this container.

        Path addressing because there is no wildcard DNS for a bucket
        subdomain on localhost — the same reason a self-hosted deployment
        needs it.
        """
        return {
            "s3_endpoint_url": self.endpoint_url,
            "s3_bucket": S3_BUCKET,
            "s3_access_key": S3_USER,
            "s3_secret_key": S3_PASSWORD,
            "s3_region": "us-east-1",
            "s3_addressing_style": "path",
            "s3_signature_version": "s3v4",
        }

    def _boto(self):
        """Return a boto3 client for this container."""
        import boto3
        from botocore.config import Config

        return boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=S3_USER,
            aws_secret_access_key=S3_PASSWORD,
            region_name="us-east-1",
            config=Config(
                signature_version="s3v4", s3={"addressing_style": "path"}
            ),
        )

    def create_bucket(self) -> None:
        """Create the test bucket, ignoring one that already exists."""
        client = self._boto()

        try:
            client.create_bucket(Bucket=S3_BUCKET)
        except client.exceptions.BucketAlreadyOwnedByYou:
            pass

    def empty_bucket(self) -> None:
        """Delete every object in the test bucket."""
        client = self._boto()
        listed = client.list_objects_v2(Bucket=S3_BUCKET)
        keys = [{"Key": obj["Key"]} for obj in listed.get("Contents", [])]

        if keys:
            client.delete_objects(Bucket=S3_BUCKET, Delete={"Objects": keys})
