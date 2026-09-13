"""Tests for the content-addressed object layout."""

import pytest

from spyglass_store.storage import LAYOUT_VERSION, ObjectStore, object_key

VALID = "a" * 64


def test_key_is_derived_from_the_hash() -> None:
    """The key fans out two levels, then repeats the full digest."""
    sha = "0123456789abcdef" * 4
    assert object_key(sha) == f"spyglass/{LAYOUT_VERSION}/01/23/{sha}"


def test_identical_content_yields_identical_keys() -> None:
    """Deduplication falls out of content addressing."""
    assert object_key(VALID) == object_key(VALID)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "a" * 63,  # too short
        "a" * 65,  # too long
        "A" * 64,  # uppercase
        "g" * 64,  # not hex
        "../" + "a" * 61,  # path traversal
    ],
)
def test_malformed_digests_are_rejected(bad: str) -> None:
    """A key is never built from unvalidated input.

    The traversal case matters most: keys reach the object store directly, so
    a digest is validated rather than trusted.
    """
    with pytest.raises(ValueError, match="hex digest"):
        object_key(bad)


def test_object_store_protocol_is_structural() -> None:
    """An adapter satisfies the protocol without inheriting from it.

    Keeps the choice among Ceph RGW, SeaweedFS, and Garage reversible.
    """

    class Fake:
        def exists(self, key: str) -> bool:
            return False

        def presigned_get(self, key: str, ttl_seconds: int) -> str:
            return "https://example.invalid/get"

        def size(self, key: str) -> int | None:
            return 0

        def presigned_put(self, key: str, ttl_seconds: int) -> str:
            return "https://example.invalid/put"

    assert isinstance(Fake(), ObjectStore)


def test_same_origin_compares_scheme_host_and_port():
    """Origin is what decides header forwarding, not string similarity."""
    from spyglass_store.app import same_origin

    assert same_origin("https://a.org/api", "https://a.org/objects")
    assert not same_origin("https://a.org", "https://objects.a.org")
    assert not same_origin("https://a.org", "http://a.org")
    assert not same_origin("https://a.org:443", "https://a.org:9000")
    # An unset public_base_url cannot be compared, so it must not match.
    assert not same_origin("", "https://a.org")
