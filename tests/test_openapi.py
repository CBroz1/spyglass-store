"""Checks on the API contract itself.

`openapi.yaml` is the source of truth for both this service and the Spyglass
client, so it is worth guarding against drift even before the endpoints exist.
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

SPEC_PATH = Path(__file__).resolve().parents[1] / "openapi.yaml"

#: Every endpoint the Spyglass client depends on. Removing one is a breaking
#: change that requires a new version path, not an edit here.
REQUIRED_OPERATIONS = {
    ("/auth/device", "post"),
    ("/auth/token", "post"),
    ("/file/resolve", "get"),
    ("/file", "post"),
    ("/file/{file_id}/content", "get"),
    ("/file/{file_id}/visibility", "patch"),
}


@pytest.fixture(scope="module")
def spec() -> dict:
    """Parsed contract."""
    return yaml.safe_load(SPEC_PATH.read_text())


def test_contract_covers_every_client_operation(spec: dict) -> None:
    """The client's needs and the contract stay in step."""
    present = {
        (path, method)
        for path, ops in spec["paths"].items()
        for method in ops
        if method in {"get", "post", "patch", "put", "delete"}
    }
    assert REQUIRED_OPERATIONS <= present


def test_server_url_is_version_pinned(spec: dict) -> None:
    """A broker upgrade must not break pinned clients."""
    assert spec["servers"][0]["url"].endswith("/api/v1")


def test_operations_have_unique_ids(spec: dict) -> None:
    """Generators rely on operationId being present and unique."""
    ids = [
        op["operationId"]
        for ops in spec["paths"].values()
        for method, op in ops.items()
        if method in {"get", "post", "patch", "put", "delete"}
    ]
    assert len(ids) == len(set(ids)) == len(REQUIRED_OPERATIONS)


def test_auth_endpoints_are_the_only_unauthenticated_ones(spec: dict) -> None:
    """Everything except login requires a bearer token."""
    public = {
        path
        for path, ops in spec["paths"].items()
        for method, op in ops.items()
        if method in {"get", "post", "patch"} and op.get("security") == []
    }
    assert public == {"/auth/device", "/auth/token"}


def test_content_endpoint_redirects_rather_than_serving_bytes(
    spec: dict,
) -> None:
    """The broker stays out of the data path.

    A 200 here would mean proxying file bytes, which would put the broker in
    the transfer path for multi-terabyte reads.
    """
    responses = spec["paths"]["/file/{file_id}/content"]["get"]["responses"]
    assert "302" in responses
    assert "200" not in responses


def test_throttling_tells_the_client_when_to_retry(spec: dict) -> None:
    """429 carries Retry-After so clients back off instead of failing."""
    throttled = spec["components"]["responses"]["Throttled"]
    assert "Retry-After" in throttled["headers"]


def test_secured_operations_document_401(spec: dict) -> None:
    """A secured endpoint has to say what an unusable token gets back.

    401 and 403 are different answers: 401 means the caller was never
    identified and a valid token may work, 403 means a known identity was
    refused. A client that cannot tell them apart retries the wrong one.
    """
    missing = [
        f"{path} {method}"
        for path, ops in spec["paths"].items()
        for method, op in ops.items()
        if method in {"get", "post", "patch"}
        and op.get("security") != []
        and "401" not in op["responses"]
    ]
    assert not missing, f"secured operations without a 401: {missing}"
