"""S3 adapter, satisfying the `ObjectStore` protocol.

Written against the S3 API rather than any one implementation, so the choice
among Ceph RGW, SeaweedFS, and Garage stays a deployment decision: point
`s3_endpoint_url` at whichever is running. That is why the storage decision
does not block this code.

`boto3` is a hard dependency, not an extra: presigning S3 URLs is the whole
job. Tests still inject a fake client, but that is a test seam rather than a
reason to make the real one optional.
"""

from __future__ import annotations

import boto3
from botocore.config import Config

from spyglass_store.settings import Settings, get_settings
from spyglass_store.storage import PresignedUpload, checksum_header


class S3ObjectStore:
    """Presign and probe objects in an S3-compatible bucket.

    The broker holds the only credentials that can write to the bucket, and
    never proxies bytes: it hands out time-limited URLs and steps out of the
    data path.
    """

    #: Matches the protocol; nothing here streams on the broker's behalf.
    name = "s3"

    def __init__(self, settings: Settings | None = None, client=None):
        """Build an adapter.

        Parameters
        ----------
        settings : Settings, optional
            Configuration. Defaults to the process settings.
        client : optional
            Pre-built boto3 client. Supplied by tests; when omitted, one is
            constructed from `settings`.
        """
        self.settings = settings or get_settings()
        self._client = client or self._build_client()

    def client_kwargs(self) -> dict:
        """Return the arguments for `boto3.client`, minus the botocore config.

        Split out so the wiring is assertable without building a client.

        Returns
        -------
        dict
            Keyword arguments. Empty settings become None so boto3 falls back
            to its own credential chain, which is what an IAM-role deployment
            wants.
        """
        cfg = self.settings

        return {
            "endpoint_url": cfg.s3_endpoint_url or None,
            "region_name": cfg.s3_region or None,
            "aws_access_key_id": cfg.s3_access_key or None,
            "aws_secret_access_key": cfg.s3_secret_key or None,
        }

    def botocore_config_kwargs(self) -> dict:
        """Return the arguments for `botocore.config.Config`.

        These are the settings that differ between S3 implementations, so they
        are configuration rather than constants.

        Returns
        -------
        dict
            Signature version and addressing style.
        """
        return {
            "signature_version": self.settings.s3_signature_version,
            "s3": {"addressing_style": self.settings.s3_addressing_style},
        }

    def _build_client(self):
        """Construct a boto3 S3 client from settings."""
        return boto3.client(
            "s3",
            config=Config(**self.botocore_config_kwargs()),
            **self.client_kwargs(),
        )

    def verify_store(self) -> None:
        """Check the bucket is reachable with the configured credentials.

        Call once at startup, alongside `lab.verify_lab_schema`. A wrong
        endpoint, region, or key otherwise surfaces as a failed upload for
        whichever user happens to go first.

        Raises
        ------
        RuntimeError
            If the bucket cannot be reached, with the endpoint and bucket
            named so the operator can tell config error from outage.
        """
        cfg = self.settings
        try:
            self._client.head_bucket(Bucket=cfg.s3_bucket)
        except Exception as err:  # noqa: BLE001 - botocore errors vary
            raise RuntimeError(
                f"Cannot reach bucket {cfg.s3_bucket!r} at "
                f"{cfg.s3_endpoint_url or 'the default AWS endpoint'} "
                f"(region {cfg.s3_region!r}, {cfg.s3_addressing_style} "
                f"addressing). Check deploy/README.md for a profile matching "
                f"your backend.\n  {err}"
            ) from err

    def exists(self, key: str) -> bool:
        """Return True if an object is present at `key`.

        Used to deduplicate: a registration whose content hash is already
        stored needs no upload.
        """
        try:
            self._client.head_object(Bucket=self.settings.s3_bucket, Key=key)
        except Exception as err:  # noqa: BLE001 - botocore errors vary by store
            if _is_not_found(err):
                return False
            raise

        return True

    def read_range(self, key: str, offset: int, length: int) -> bytes | None:
        """Return a bounded range of an object, or None if it is absent.

        Parameters
        ----------
        key : str
            Object key.
        offset : int
            First byte to read.
        length : int
            How many bytes.

        Returns
        -------
        bytes or None
        """
        last = offset + length - 1

        try:
            response = self._client.get_object(
                Bucket=self.settings.s3_bucket,
                Key=key,
                Range=f"bytes={offset}-{last}",
            )
        except Exception as err:  # noqa: BLE001 - botocore errors vary
            if _is_not_found(err):
                return None
            raise

        return response["Body"].read()

    def size(self, key: str) -> int | None:
        """Return the stored size of `key`, or None if it is not there.

        Read from the store rather than trusted from the client, because the
        declared size is what quota charges and what the audit reports.

        Parameters
        ----------
        key : str
            Object key.

        Returns
        -------
        int or None
        """
        try:
            head = self._client.head_object(
                Bucket=self.settings.s3_bucket, Key=key
            )
        except Exception as err:  # noqa: BLE001 - botocore errors vary
            if _is_not_found(err):
                return None
            raise

        return int(head["ContentLength"])

    def iter_keys(self, prefix: str = ""):
        """Yield every object key under `prefix`.

        Not part of `ObjectStore`: reconciliation is the only caller, and a
        listing is the one operation a store can make expensive. Keeping it
        off the protocol means a backend that cannot list cheaply is still a
        valid backend, and only the admin report degrades.

        Parameters
        ----------
        prefix : str, optional
            Key prefix to walk.

        Yields
        ------
        str
        """
        paginator = self._client.get_paginator("list_objects_v2")

        for page in paginator.paginate(
            Bucket=self.settings.s3_bucket, Prefix=prefix
        ):
            for obj in page.get("Contents", []):
                yield obj["Key"]

    def presigned_get(self, key: str, ttl_seconds: int | None = None) -> str:
        """Return a time-limited URL for reading `key`.

        Short-lived on purpose: once issued, the broker cannot revoke or meter
        the transfer, so quota is charged at issue time and the window is kept
        small.
        """
        return self._presign("get_object", key, ttl_seconds)

    def presigned_put(
        self,
        key: str,
        ttl_seconds: int | None = None,
        sha256: str | None = None,
    ) -> PresignedUpload:
        """Return a time-limited target for writing `key`.

        When `sha256` is given and checksum enforcement is on, the digest is
        signed into the URL as a required header. The store then computes the
        hash of what arrives and refuses a mismatch, which is the only way to
        bind registered content to uploaded content without the broker
        standing in the data path.

        Because the requirement is part of the signature, a client cannot skip
        it: omitting the header invalidates the request rather than waiving
        the check.

        Parameters
        ----------
        key : str
            Object key to write.
        ttl_seconds : int, optional
            Lifetime. Defaults to the configured presign TTL.
        sha256 : str, optional
            Hex digest the uploaded bytes must hash to.

        Returns
        -------
        PresignedUpload
            URL, and the headers the client must send.
        """
        params = {"Bucket": self.settings.s3_bucket, "Key": key}
        headers: dict[str, str] = {}

        if sha256 and self.settings.s3_enforce_upload_checksum:
            encoded = checksum_header(sha256)
            params["ChecksumSHA256"] = encoded
            headers["x-amz-checksum-sha256"] = encoded

        url = self._client.generate_presigned_url(
            "put_object",
            Params=params,
            ExpiresIn=ttl_seconds or self.settings.presigned_ttl_seconds,
        )

        return PresignedUpload(url, headers)

    def _presign(self, operation: str, key: str, ttl: int | None) -> str:
        """Sign one request."""
        return self._client.generate_presigned_url(
            operation,
            Params={"Bucket": self.settings.s3_bucket, "Key": key},
            ExpiresIn=ttl or self.settings.presigned_ttl_seconds,
        )


def _is_not_found(err: Exception) -> bool:
    """Return True if an error means "no such object".

    Implementations disagree on the shape: botocore raises `ClientError` with
    a 404 or a `404`/`NoSuchKey` code, and some report `NoSuchKey` where others
    report `NotFound`. Checked structurally rather than by exception class so
    the adapter stays implementation-agnostic.
    """
    response = getattr(err, "response", None)
    if not isinstance(response, dict):
        return False

    error = response.get("Error", {})
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")

    return status == 404 or str(error.get("Code")) in {
        "404",
        "NoSuchKey",
        "NotFound",
    }
