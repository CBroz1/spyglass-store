"""Integration tests against a containerized S3 store.

These run against a real S3 implementation rather than a mock. Presigning is
the one part of the adapter a stub cannot stand in for — a fake can return a
string shaped like a URL, but only a real store will tell you whether the
signature it carries is one it accepts.

MinIO stands in for the deployment. Because the adapter speaks only the S3 API,
pointing these at Ceph RGW, SeaweedFS, or Garage is an endpoint change; that
reversibility is itself what is under test.
"""

from __future__ import annotations

import time

import httpx
import pytest

from spyglass_store.storage import object_key

SHA = "c" * 64
PAYLOAD = b"synthetic nwb bytes, not real data\n"


@pytest.fixture
def stored(object_store):
    """One object actually written through a presigned PUT."""
    key = object_key(SHA)
    upload = object_store.presigned_put(key, 300)

    response = httpx.put(upload.url, content=PAYLOAD, headers=upload.headers)
    response.raise_for_status()

    return key


def test_presigned_put_accepts_bytes(object_store, stored):
    """The upload half: a signed URL the store actually honours."""
    assert object_store.exists(stored)


def test_presigned_get_returns_the_bytes(object_store, stored):
    """The download half, which is what the content redirect hands out."""
    url = object_store.presigned_get(stored, 300)

    response = httpx.get(url)

    assert response.status_code == 200
    assert response.content == PAYLOAD


def test_exists_is_false_for_absent_content(object_store):
    """Deduplication turns on this answer, so a miss must not raise."""
    assert not object_store.exists(object_key("d" * 64))


def test_verify_store_passes_against_a_real_bucket(object_store):
    """The startup check must accept a correctly configured store."""
    object_store.verify_store()  # raises on failure


def test_verify_store_names_the_bucket_it_could_not_reach(s3_settings):
    """A misconfiguration should be diagnosable from the error alone."""
    from spyglass_store.s3 import S3ObjectStore

    wrong = S3ObjectStore(s3_settings.model_copy(update={"s3_bucket": "nope"}))

    with pytest.raises(RuntimeError, match="nope"):
        wrong.verify_store()


def test_a_signature_expires(object_store, stored):
    """Short TTLs are the reason the broker can leave the data path.

    An issued URL cannot be revoked, so its lifetime is the only bound on how
    long a decision stays in force.
    """
    url = object_store.presigned_get(stored, 1)
    time.sleep(2)

    assert httpx.get(url).status_code == 403


def test_an_unsigned_request_is_refused(object_store, stored):
    """Without a signature the bucket must give nothing away.

    If this passed, the bucket would be public and every permission decision
    above it decorative.
    """
    unsigned = object_store.presigned_get(stored, 300).split("?")[0]

    assert httpx.get(unsigned).status_code == 403


def test_a_tampered_key_is_refused(object_store, stored):
    """A signature covers the key, so it cannot be repointed at another."""
    url = object_store.presigned_get(stored, 300)
    other = url.replace(SHA, "e" * 64)

    assert httpx.get(other).status_code == 403


# ------------------ a stray Authorization header ------------------


def test_presigned_get_rejects_a_stray_authorization_header(
    object_store, stored
):
    """A presigned GET must refuse a request carrying `Authorization`.

    This is the verb the content redirect uses. A client that forwarded its
    broker credential across the 302 would land here, and the store refuses —
    which is why the broker and the object store must not share an origin.

    The header does not cause a signature mismatch; it switches the store out
    of presigned-URL mode into header authentication, which then demands a
    header the client never sent.
    """
    url = object_store.presigned_get(stored, 300)

    clean = httpx.get(url)
    with_auth = httpx.get(url, headers={"Authorization": "Bearer broker-tok"})

    assert clean.status_code == 200
    assert with_auth.status_code >= 400


def test_a_cross_origin_redirect_strips_the_header(object_store, stored):
    """The reason the design is safe: clients drop the header themselves.

    Verified here against a real signed URL rather than a local stand-in, so
    the client behaviour and the store's refusal are observed together.
    """
    url = object_store.presigned_get(stored, 300)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/content":
            return httpx.Response(302, headers={"Location": url})
        raise AssertionError("unreachable")  # pragma: no cover

    # Only the broker hop is simulated; the redirect target is the real store.
    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        hop = client.get(
            "https://broker.example.org/content",
            headers={"Authorization": "Bearer broker-tok"},
        )

    assert hop.status_code == 302

    followed = httpx.get(hop.headers["location"])

    assert followed.status_code == 200
    assert followed.content == PAYLOAD


# --------------------------- startup checks ---------------------------


def test_startup_verifies_the_store(db, s3_settings, object_store):
    """A broker that boots has already proved it can reach its bucket."""
    from fastapi.testclient import TestClient

    from spyglass_store.app import create_app

    app = create_app(store=object_store, github=object(), settings=s3_settings)

    with TestClient(app):  # entering runs lifespan
        pass


def test_startup_fails_on_an_unreachable_bucket(db, s3_settings):
    """Better to refuse to start than to fail under the first user."""
    from fastapi.testclient import TestClient

    from spyglass_store.app import create_app
    from spyglass_store.s3 import S3ObjectStore

    wrong = S3ObjectStore(s3_settings.model_copy(update={"s3_bucket": "nope"}))
    app = create_app(store=wrong, github=object(), settings=s3_settings)

    with pytest.raises(RuntimeError, match="nope"):
        with TestClient(app):
            pass  # pragma: no cover - lifespan raises before the body


def test_same_origin_deployment_is_warned_about(
    db, s3_settings, object_store, caplog
):
    """The configuration that silently breaks reads should be loud at boot."""
    import logging

    from spyglass_store.app import verify_deployment

    shared = s3_settings.model_copy(
        update={"public_base_url": s3_settings.s3_endpoint_url}
    )

    with caplog.at_level(logging.WARNING):
        verify_deployment(shared, object_store)

    assert "share an origin" in caplog.text


def test_different_origins_are_not_warned_about(
    db, s3_settings, object_store, caplog
):
    import logging

    from spyglass_store.app import verify_deployment

    apart = s3_settings.model_copy(
        update={"public_base_url": "https://broker.example.org"}
    )

    with caplog.at_level(logging.WARNING):
        verify_deployment(apart, object_store)

    assert "share an origin" not in caplog.text
