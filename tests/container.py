"""A throwaway MySQL container for the test suite.

Pared down from `spyglass/tests/container.py`. The broker needs far less than
Spyglass does — no per-pipeline grants, no populated data directory, no
alternate MySQL versions — so what remains is: start a container, wait for it
to become healthy, hand back DataJoint credentials, and remove it afterwards.

The container is named and ported deterministically, so a repeat run reuses the
one already up instead of racing a second server onto the same port. CI gets a
fresh runner each time and so always starts new.
"""

from __future__ import annotations

import hashlib
import socket
import time

CONTAINER_NAME = "spyglass-store-pytest"
IMAGE = "datajoint/mysql:8.0"
PASSWORD = "tutorial"
USER = "root"


def _port_for(name: str, low: int = 10240, high: int = 60000) -> int:
    """Derive a stable port from a container name.

    A fixed default would collide with whatever else is already bound; hashing
    the name keeps repeat runs on one port without coordinating.
    """
    digest = int(hashlib.sha256(name.encode()).hexdigest(), 16)

    return low + (digest % (high - low + 1))


def _in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if `port` is already bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return False
        except OSError:
            return True


class MySQLContainer:
    """Start and stop a MySQL server in Docker.

    Parameters
    ----------
    name : str, optional
        Container name. Defaults to `CONTAINER_NAME`.
    keep : bool, optional
        Leave the container running on exit. Useful when iterating on tests;
        the next run reuses it rather than paying startup again.
    """

    def __init__(self, name: str = CONTAINER_NAME, keep: bool = False):
        import docker

        self.docker = docker
        self.client = docker.from_env()
        self.name = name
        self.keep = keep
        self.port = self._resolve_port()

    def _existing(self):
        """Return the container with our name, or None."""
        try:
            return self.client.containers.get(self.name)
        except self.docker.errors.NotFound:
            return None

    def _resolve_port(self) -> int:
        """Reuse a running container's port, else pick a free one."""
        container = self._existing()

        if container is not None:
            bindings = container.attrs["NetworkSettings"]["Ports"]
            bound = bindings.get("3306/tcp")
            if bound:
                return int(bound[0]["HostPort"])

        port = _port_for(self.name)
        while _in_use(port):
            port += 1

        return port

    def start(self) -> None:
        """Start the container, reusing or restarting one if it exists."""
        container = self._existing()

        if container is None:
            self.client.containers.run(
                image=IMAGE,
                name=self.name,
                ports={3306: self.port},
                environment=[
                    f"MYSQL_ROOT_PASSWORD={PASSWORD}",
                    "MYSQL_DEFAULT_STORAGE_ENGINE=InnoDB",
                ],
                detach=True,
                tty=True,
            )
            return

        container.reload()
        if container.status == "exited":
            container.restart()

    def wait(self, timeout: int = 180, interval: int = 2) -> None:
        """Block until the server reports healthy.

        Parameters
        ----------
        timeout : int, optional
            Seconds to wait before giving up.
        interval : int, optional
            Seconds between checks.

        Raises
        ------
        RuntimeError
            If the container is not healthy within `timeout`. Failing loudly
            beats letting every test fail on connection refused.
        """
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            container = self._existing()
            if container is not None:
                container.reload()
                if container.health == "healthy":
                    return
            time.sleep(interval)

        raise RuntimeError(
            f"Container {self.name} did not become healthy in {timeout}s. "
            "Check `docker logs " + self.name + "`."
        )

    @property
    def credentials(self) -> dict:
        """DataJoint config for this container."""
        return {
            "database.host": "127.0.0.1",
            "database.user": USER,
            "database.password": PASSWORD,
            "database.port": self.port,
            "safemode": False,
        }

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
        container.remove()
