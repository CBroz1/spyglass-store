"""Tests for the S3 adapter, with a stubbed client.

No network: the adapter is injected with a fake client, which
also proves the constructor seam exists for the integration tests that will
run against a containerized store.
"""

import pytest

from spyglass_store.s3 import S3ObjectStore, _is_not_found
from spyglass_store.settings import Settings
from spyglass_store.storage import ObjectStore, object_key

BUCKET = "test-bucket"
KEY = object_key("b" * 64)


class _FakeClient:
    """Records calls; raises whatever `head_error` is set to."""

    def __init__(self, head_error: Exception | None = None):
        self.head_error = head_error
        self.presigned: list[tuple] = []

    def head_object(self, Bucket: str, Key: str) -> dict:  # noqa: N803
        if self.head_error:
            raise self.head_error
        return {}

    def generate_presigned_url(
        self, operation: str, Params: dict, ExpiresIn: int
    ) -> str:  # noqa: N803
        self.presigned.append((operation, Params, ExpiresIn))
        return f"https://store.invalid/{Params['Key']}?op={operation}"


def client_error(code: str = "404", status: int = 404) -> Exception:
    """Build an exception shaped like a botocore ClientError."""
    err = Exception("not found")
    err.response = {
        "Error": {"Code": code},
        "ResponseMetadata": {"HTTPStatusCode": status},
    }
    return err


@pytest.fixture
def store() -> S3ObjectStore:
    settings = Settings(s3_bucket=BUCKET, presigned_ttl_seconds=300)
    return S3ObjectStore(settings=settings, client=_FakeClient())


def test_satisfies_the_object_store_protocol(store) -> None:
    """Structural check, so an alternative adapter needs no inheritance."""
    assert isinstance(store, ObjectStore)


def test_existing_object_is_reported_present(store) -> None:
    assert store.exists(KEY) is True


@pytest.mark.parametrize(
    "err",
    [
        client_error("404", 404),
        client_error("NoSuchKey", 404),
        client_error("NotFound", 404),
    ],
    ids=["numeric", "no-such-key", "not-found"],
)
def test_missing_object_is_reported_absent(err) -> None:
    """Implementations disagree on the not-found shape; all mean absent."""
    store = S3ObjectStore(
        settings=Settings(s3_bucket=BUCKET),
        client=_FakeClient(head_error=err),
    )
    assert store.exists(KEY) is False


def test_unexpected_errors_are_not_swallowed() -> None:
    """A permission failure must not be mistaken for a missing object.

    Reporting absent here would silently re-upload data that already exists,
    or worse, mask a misconfigured bucket policy.
    """
    denied = client_error("AccessDenied", 403)
    store = S3ObjectStore(
        settings=Settings(s3_bucket=BUCKET), client=_FakeClient(denied)
    )
    with pytest.raises(Exception, match="not found"):
        store.exists(KEY)


def test_presigned_get_uses_the_configured_bucket_and_ttl(store) -> None:
    store.presigned_get(KEY)
    operation, params, expires = store._client.presigned[0]

    assert operation == "get_object"
    assert params == {"Bucket": BUCKET, "Key": KEY}
    assert expires == 300


def test_presigned_put_signs_a_write(store) -> None:
    store.presigned_put(KEY)
    assert store._client.presigned[0][0] == "put_object"


def test_explicit_ttl_overrides_the_default(store) -> None:
    store.presigned_get(KEY, ttl_seconds=30)
    assert store._client.presigned[0][2] == 30


def test_non_dict_response_is_not_treated_as_missing() -> None:
    """A bare exception carries no not-found evidence, so it propagates."""
    assert _is_not_found(ValueError("boom")) is False


# --------------------------------------------------------------------------- #
# Backend interchangeability
# --------------------------------------------------------------------------- #
R2 = Settings(
    s3_endpoint_url="https://acct.r2.cloudflarestorage.com",
    s3_bucket=BUCKET,
    s3_access_key="key",
    s3_secret_key="secret",
    s3_region="auto",
)


def test_defaults_suit_custom_endpoints() -> None:
    """Path addressing and SigV4, which R2 and self-hosted stores require.

    Virtual-hosted addressing assumes the bucket is a subdomain, which needs
    wildcard DNS that self-hosted options generally lack.
    """
    store = S3ObjectStore(settings=Settings(), client=_FakeClient())
    cfg = store.botocore_config_kwargs()

    assert cfg["signature_version"] == "s3v4"
    assert cfg["s3"]["addressing_style"] == "path"


def test_r2_profile_is_passed_through() -> None:
    """R2 needs region 'auto'; boto3 cannot infer it from the endpoint."""
    store = S3ObjectStore(settings=R2, client=_FakeClient())
    kwargs = store.client_kwargs()

    assert kwargs["endpoint_url"] == "https://acct.r2.cloudflarestorage.com"
    assert kwargs["region_name"] == "auto"
    assert kwargs["aws_access_key_id"] == "key"


def test_aws_profile_is_expressible() -> None:
    """The same code serves AWS by changing settings, not branching."""
    aws = Settings(
        s3_bucket=BUCKET,
        s3_region="us-west-2",
        s3_addressing_style="virtual",
    )
    store = S3ObjectStore(settings=aws, client=_FakeClient())

    assert store.client_kwargs()["endpoint_url"] is None  # AWS default
    assert store.client_kwargs()["region_name"] == "us-west-2"
    assert store.botocore_config_kwargs()["s3"]["addressing_style"] == "virtual"


def test_blank_credentials_defer_to_the_boto3_chain() -> None:
    """An IAM-role deployment supplies no keys; empty must not mean empty."""
    store = S3ObjectStore(
        settings=Settings(s3_bucket=BUCKET), client=_FakeClient()
    )
    kwargs = store.client_kwargs()

    assert kwargs["aws_access_key_id"] is None
    assert kwargs["aws_secret_access_key"] is None


def test_switching_backends_preserves_object_keys() -> None:
    """Keys are content-derived, so a bucket migration is a copy.

    Nothing backend-specific may leak into the key, or migration would mean
    rewriting the registry.
    """
    key = object_key("c" * 64)
    r2 = S3ObjectStore(settings=R2, client=_FakeClient())
    local = S3ObjectStore(
        settings=Settings(
            s3_endpoint_url="http://store:8333", s3_bucket=BUCKET
        ),
        client=_FakeClient(),
    )

    r2.presigned_get(key)
    local.presigned_get(key)

    assert r2._client.presigned[0][1]["Key"] == key
    assert local._client.presigned[0][1]["Key"] == key


# --------------------------------------------------------------------------- #
# Startup check
# --------------------------------------------------------------------------- #
class _HeadBucketClient(_FakeClient):
    def __init__(self, error: Exception | None = None):
        super().__init__()
        self.bucket_error = error

    def head_bucket(self, Bucket: str) -> dict:  # noqa: N803
        if self.bucket_error:
            raise self.bucket_error
        return {}


def test_reachable_bucket_verifies_quietly() -> None:
    store = S3ObjectStore(settings=R2, client=_HeadBucketClient())
    store.verify_store()  # no raise


def test_unreachable_bucket_names_the_configuration() -> None:
    """Operators need to tell a config error from an outage."""
    store = S3ObjectStore(
        settings=R2, client=_HeadBucketClient(client_error("403", 403))
    )

    with pytest.raises(RuntimeError) as err:
        store.verify_store()

    message = str(err.value)
    assert BUCKET in message
    assert "r2.cloudflarestorage.com" in message
    assert "auto" in message  # the region, a common R2 misconfiguration


def test_both_integrity_headers_are_signed_when_both_are_known():
    """The adapter sends `Content-MD5` alongside the SHA-256 checksum.

    Stores disagree about which they honour — Ceph RGW signs
    `x-amz-checksum-sha256` and then ignores the bytes, while enforcing
    `Content-MD5`; MinIO and R2 check both. Sending both leaves each store
    enforcing the strongest check it supports, and none weaker than before.

    What is asserted here is what this package does: the values are signed
    into the request and returned for the client to send. Whether a particular
    store then honours them is that store's behaviour, not this package's.
    """
    import base64
    import hashlib

    payload = b"both headers"
    sha = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()

    client = _FakeClient()
    store = S3ObjectStore(Settings(s3_bucket=BUCKET), client=client)
    upload = store.presigned_put(KEY, 300, sha256=sha, content_md5=md5)

    _, params, _ = client.presigned[-1]

    assert (
        params["ChecksumSHA256"]
        == base64.b64encode(bytes.fromhex(sha)).decode()
    )
    assert params["ContentMD5"] == base64.b64encode(bytes.fromhex(md5)).decode()
    assert upload.headers == {
        "x-amz-checksum-sha256": params["ChecksumSHA256"],
        "Content-MD5": params["ContentMD5"],
    }, "the client has to send exactly what was signed"


def test_an_absent_md5_signs_only_the_checksum():
    """It is optional: a client that sends no MD5 still gets an upload URL."""
    client = _FakeClient()
    store = S3ObjectStore(Settings(s3_bucket=BUCKET), client=client)
    upload = store.presigned_put(KEY, 300, sha256="a" * 64)

    _, params, _ = client.presigned[-1]

    assert "ContentMD5" not in params
    assert "Content-MD5" not in upload.headers
    assert "x-amz-checksum-sha256" in upload.headers


def test_md5_header_converts_hex_to_base64():
    """S3 carries the digest base64; the registry speaks hex."""
    import base64
    import hashlib

    from spyglass_store.storage import md5_header

    payload = b"conversion check"
    expected = base64.b64encode(hashlib.md5(payload).digest()).decode()

    assert md5_header(hashlib.md5(payload).hexdigest()) == expected


def test_md5_header_refuses_anything_that_is_not_a_hex_digest():
    """A malformed digest must fail here, not as an opaque 403 from the store."""
    import pytest

    from spyglass_store.storage import md5_header

    for bad in ("", "xyz", "0" * 31, "0" * 33, "A" * 32):
        with pytest.raises(ValueError, match="32-character"):
            md5_header(bad)


def test_enforcement_off_signs_neither_header():
    """One switch governs both, so turning it off is unambiguous."""
    from spyglass_store.s3 import S3ObjectStore
    from spyglass_store.settings import Settings

    store = S3ObjectStore(
        Settings(
            s3_endpoint_url="https://objects.example.org",
            s3_access_key="k",
            s3_secret_key="s",
            s3_enforce_upload_checksum=False,
        )
    )
    upload = store.presigned_put(
        "k", 300, sha256="a" * 64, content_md5="b" * 32
    )

    assert upload.headers == {}
