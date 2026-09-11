"""Tests for the broker's read path.

No database, no bucket, no network: `registry` is patched with in-memory rows
and the verifier and object store are injected. What is under test is the
decision and the shape of the response, and neither needs infrastructure.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from spyglass_store.access import AccessRule, Principal
from spyglass_store.app import create_app
from spyglass_store.auth import Identity
from spyglass_store.registry import FileRecord
from spyglass_store.settings import Settings
from spyglass_store.storage import object_key

SHA = "a" * 64

OWNER = FileRecord(
    file_id="f1",
    sha256=SHA,
    size_bytes=1024,
    spyglass_name="session1_.nwb",
    file_class="raw",
    owner="7",
)

#: Identity per token. Mirrors what GitHub plus the account lookup would give.
IDENTITIES = {
    "owner": Identity(1, "owner", account_id="7", tier="verified"),
    "teammate": Identity(
        2, "mate", account_id="8", tier="verified", teams=frozenset({"teamA"})
    ),
    "stranger": Identity(3, "stranger", account_id="9", tier="verified"),
    "unverified": Identity(4, "new", account_id="10", tier="unverified"),
    "unregistered": Identity(5, "nobody"),  # authenticated, no broker account
}


class _Verifier:
    """Maps a token straight to an identity."""

    def verify(self, token):
        return IDENTITIES.get(token)


class _Store:
    """Records what was presigned and returns a fixed URL.

    `has_object` flips whether the content is already stored, which is what
    decides deduplication on the registration path.
    """

    def __init__(self):
        self.presigned = []
        self.put_presigned = []
        self.has_object = False

    def presigned_get(self, key, ttl_seconds):
        self.presigned.append((key, ttl_seconds))
        return f"https://objects.example.org/{key}?sig=abc"

    def exists(self, key):
        return self.has_object

    def presigned_put(self, key, ttl):
        self.put_presigned.append((key, ttl))
        return f"https://objects.example.org/{key}?sig=put"


@pytest.fixture
def store():
    return _Store()


@pytest.fixture
def client(store):
    """A client whose registry is patched to a single owned file."""
    app = create_app(
        verifier=_Verifier(),
        store=store,
        settings=Settings(presigned_ttl_seconds=300),
    )

    with (
        patch(
            "spyglass_store.registry.resolve_account", side_effect=lambda i: i
        ),
        patch("spyglass_store.registry.file_by_id", side_effect=_by_id),
        patch("spyglass_store.registry.file_by_name", side_effect=_by_name),
        patch("spyglass_store.registry.file_by_sha256", side_effect=_by_sha),
        patch("spyglass_store.registry.rules_for_file", side_effect=_rules),
        patch(
            "spyglass_store.registry.registration_for",
            side_effect=_registration_for,
        ),
        patch(
            "spyglass_store.registry.register_file", side_effect=_register_file
        ),
    ):
        yield TestClient(app)


#: Registrations made through the route, keyed by (sha256, name, owner).
_REGISTERED: dict = {}


def _registration_for(sha256, name, owner):
    return _REGISTERED.get((sha256, name, owner))


def _register_file(
    *, sha256, size_bytes, spyglass_name, file_class, owner, rules=()
):
    record = FileRecord(
        file_id=f"id{len(_REGISTERED)}",
        sha256=sha256,
        size_bytes=size_bytes,
        spyglass_name=spyglass_name,
        file_class=file_class,
        owner=owner,
    )
    _REGISTERED[(sha256, spyglass_name, owner)] = record
    return record


@pytest.fixture(autouse=True)
def _clear_registrations():
    _REGISTERED.clear()
    yield
    _REGISTERED.clear()


#: Grants on the one file. Rebound per test via `set_rules`.
_CURRENT_RULES: list[AccessRule] = []


def set_rules(*rules):
    _CURRENT_RULES[:] = rules


def _rules(file_id):
    return tuple(_CURRENT_RULES)


def _by_id(file_id):
    return OWNER if file_id == OWNER.file_id else None


def _by_name(name):
    return OWNER if name == OWNER.spyglass_name else None


def _by_sha(sha):
    return OWNER if sha == OWNER.sha256 else None


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------- authentication ---------------------------


def test_missing_token_is_401(client):
    """No credential is an authentication failure, not an authorization one."""
    set_rules()
    r = client.get("/api/v1/file/resolve", params={"name": OWNER.spyglass_name})

    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_unknown_token_is_401(client):
    """A token GitHub would reject never reaches a permission decision."""
    set_rules()
    r = client.get(
        "/api/v1/file/resolve",
        params={"name": OWNER.spyglass_name},
        headers=auth("garbage"),
    )

    assert r.status_code == 401


# ------------------------------ resolve ------------------------------


def test_resolve_by_name_returns_the_contract_shape(client):
    """Every required field of the contract's File schema is present."""
    set_rules()
    r = client.get(
        "/api/v1/file/resolve",
        params={"name": OWNER.spyglass_name},
        headers=auth("owner"),
    )

    assert r.status_code == 200
    assert r.json() == {
        "file_id": "f1",
        "sha256": SHA,
        "size_bytes": 1024,
        "spyglass_name": "session1_.nwb",
        "file_class": "raw",
    }


def test_resolve_by_sha256(client):
    set_rules()
    r = client.get(
        "/api/v1/file/resolve",
        params={"sha256": SHA},
        headers=auth("owner"),
    )

    assert r.status_code == 200


def test_resolve_requires_a_selector(client):
    """Neither name nor hash is a client error, not an empty result."""
    set_rules()
    r = client.get("/api/v1/file/resolve", headers=auth("owner"))

    assert r.status_code == 422


def test_resolve_unknown_name_is_404(client):
    set_rules()
    r = client.get(
        "/api/v1/file/resolve",
        params={"name": "nope.nwb"},
        headers=auth("owner"),
    )

    assert r.status_code == 404


# ---------------------------- the decision ----------------------------


@pytest.mark.parametrize(
    "token,rules,expected",
    [
        ("owner", (), 302),  # ownership needs no grant
        ("stranger", (), 403),  # private: deny by default
        ("teammate", (AccessRule(Principal.TEAM, "teamA"),), 302),
        ("stranger", (AccessRule(Principal.TEAM, "teamA"),), 403),
        ("stranger", (AccessRule(Principal.PUBLIC),), 302),
        ("unregistered", (AccessRule(Principal.PUBLIC),), 302),
        ("unregistered", (), 403),
        ("unverified", (AccessRule(Principal.PUBLIC),), 302),
        # An unverified tier reaches public data only, whatever the grant says.
        ("unverified", (AccessRule(Principal.TEAM, "teamA"),), 403),
    ],
)
def test_read_permission_matrix(client, token, rules, expected):
    set_rules(*rules)
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth(token),
        follow_redirects=False,
    )

    assert r.status_code == expected


# ----------------------------- the redirect -----------------------------


def test_content_redirects_to_a_signed_url(client, store):
    """302 to the object store, signed for the configured lifetime."""
    set_rules()
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.status_code == 302
    assert r.headers["location"].startswith("https://objects.example.org/")
    assert store.presigned == [(object_key(SHA), 300)]


def test_redirect_is_not_cacheable(client):
    """A cached 302 would replay a signature past its expiry.

    The stable URL only works because every request re-signs; caching it
    reintroduces exactly the expiry the design exists to avoid.
    """
    set_rules()
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.headers["cache-control"] == "no-store"


def test_content_unknown_file_is_404(client):
    set_rules()
    r = client.get(
        "/api/v1/file/nosuch/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.status_code == 404


def test_denied_read_does_not_presign(client, store):
    """A refused request must not mint a URL it then declines to return."""
    set_rules()
    client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("stranger"),
        follow_redirects=False,
    )

    assert store.presigned == []


# ---------------------------- registration ----------------------------

BODY = {
    "sha256": "b" * 64,
    "size_bytes": 512,
    "spyglass_name": "new_.nwb",
    "file_class": "raw",
}


def test_register_returns_an_upload_url_for_new_content(client, store):
    """New bytes get somewhere to put them."""
    store.has_object = False
    r = client.post("/api/v1/file", json=BODY, headers=auth("owner"))

    assert r.status_code == 201
    body = r.json()
    assert body["deduplicated"] is False
    assert body["upload_url"].endswith("sig=put")
    assert store.put_presigned == [(object_key("b" * 64), 300)]


def test_register_deduplicates_existing_content(client, store):
    """Bytes already stored are not uploaded again.

    This is the ST-1.4 acceptance: a duplicate hash reuses the object rather
    than storing it twice.
    """
    store.has_object = True
    r = client.post("/api/v1/file", json=BODY, headers=auth("owner"))

    assert r.status_code == 201
    assert r.json()["deduplicated"] is True
    assert r.json()["upload_url"] is None
    assert store.put_presigned == []


def test_register_is_idempotent(client, store):
    """Retrying after a dropped response returns the same file_id."""
    first = client.post("/api/v1/file", json=BODY, headers=auth("owner"))
    second = client.post("/api/v1/file", json=BODY, headers=auth("owner"))

    assert first.json()["file_id"] == second.json()["file_id"]


def test_unverified_tier_may_not_upload(client):
    """Registration writes to shared storage; the unverified tier may not."""
    r = client.post("/api/v1/file", json=BODY, headers=auth("unverified"))

    assert r.status_code == 403


def test_unregistered_identity_may_not_upload(client):
    """With no account there is no owner to record."""
    r = client.post("/api/v1/file", json=BODY, headers=auth("unregistered"))

    assert r.status_code == 403


def test_group_visibility_needs_a_team(client):
    """'group' with no teams would silently mean private."""
    r = client.post(
        "/api/v1/file",
        json={**BODY, "visibility": {"scope": "group", "teams": []}},
        headers=auth("owner"),
    )

    assert r.status_code == 422


def test_malformed_hash_is_rejected(client):
    """The hash is the object key; a bad one would mint an unreachable path."""
    r = client.post(
        "/api/v1/file", json={**BODY, "sha256": "nope"}, headers=auth("owner")
    )

    assert r.status_code == 422
