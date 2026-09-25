"""Tests that need a real object store.

**Scope: what this package does, not what a store decides to refuse.** Signing
a URL a compatible store honours, and reading and probing objects through it —
that is what is asserted. Whether a store refuses an expired signature, a
tampered key, or a checksum mismatch is the store's behaviour, it varies
between them, and a test of it reports on the backend rather than on this code.

**No store means a red suite, not a skipped one.** An unreachable object store
is a broken test environment, and a green run that proved nothing is worse than
a failure that says so.
"""

from __future__ import annotations

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


# ------------------ a stray Authorization header ------------------


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
