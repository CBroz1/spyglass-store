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
        def verify_store(self) -> None:
            return None

        def exists(self, key: str) -> bool:
            return False

        def presigned_get(self, key: str, ttl_seconds: int) -> str:
            return "https://example.invalid/get"

        def size(self, key: str) -> int | None:
            return 0

        def read_range(self, key: str, offset: int, length: int) -> bytes:
            return b""

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


def test_a_client_strips_credentials_across_origins():
    """The invariant the whole redirect design rests on.

    Both hops go through one client, and both are recorded, so this asserts
    what the *second request actually carried* rather than what a fresh request
    happens to look like. If a client ever forwarded the header across origins,
    the object store would receive a broker token and refuse the read — which
    is why the two must be different origins.
    """
    import httpx

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "broker.example.org":
            return httpx.Response(
                302,
                headers={"Location": "https://objects.example.org/o/x?sig=a"},
            )
        return httpx.Response(200, content=b"bytes")

    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        response = client.get(
            "https://broker.example.org/content",
            headers={"Authorization": "Bearer broker-tok"},
        )

    assert response.status_code == 200
    assert len(seen) == 2, "the redirect was not followed"
    assert "authorization" in {k.lower() for k in seen[0].headers}
    assert "authorization" not in {k.lower() for k in seen[1].headers}


def test_a_client_keeps_credentials_within_one_origin():
    """The other half, and the reason the constraint is not optional.

    Serve the broker and the store under one hostname and the token rides along
    to the store, which refuses the request with a complaint about a checksum.
    """
    import httpx

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/content":
            return httpx.Response(
                302, headers={"Location": "https://one.example.org/o/x?sig=a"}
            )
        return httpx.Response(200, content=b"bytes")

    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        client.get(
            "https://one.example.org/content",
            headers={"Authorization": "Bearer broker-tok"},
        )

    assert "authorization" in {k.lower() for k in seen[1].headers}
