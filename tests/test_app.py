"""Tests for the broker's read path.

No database, no bucket, no network: `registry` is patched with in-memory rows
and the verifier and object store are injected. What is under test is the
decision and the shape of the response, and neither needs infrastructure.
"""

import pytest
from fastapi.testclient import TestClient

from spyglass_store.access import AccessRule, Principal
from spyglass_store.app import create_app
from spyglass_store.auth import Identity
from spyglass_store.registry import FileRecord, Usage
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

    `has_object` flips whether the content is already stored. It decides
    deduplication when registering, and whether a read finds bytes or a
    registration still waiting for them. Defaults to present, since most
    tests here are about the decision rather than the upload state.
    """

    def __init__(self):
        self.presigned = []
        self.put_presigned = []
        self.has_object = True

    def presigned_get(self, key, ttl_seconds):
        self.presigned.append((key, ttl_seconds))
        return f"https://objects.example.org/{key}?sig=abc"

    def exists(self, key):
        return self.has_object

    def size(self, key):
        return None  # falls back to the declared size

    def read_range(self, key, offset, length):  # pragma: no cover
        return b""

    def presigned_put(self, key, ttl, sha256=None):
        from spyglass_store.storage import PresignedUpload, checksum_header

        self.put_presigned.append((key, ttl, sha256))
        headers = (
            {"x-amz-checksum-sha256": checksum_header(sha256)} if sha256 else {}
        )
        return PresignedUpload(
            f"https://objects.example.org/{key}?sig=put", headers
        )


@pytest.fixture
def store():
    return _Store()


class _Registry:
    """An in-memory stand-in for the database layer.

    One object supplied to `create_app`, rather than eight functions patched
    onto a module. What it exposes is exactly what the routes call, so a route
    reaching for something new fails here loudly instead of silently touching
    a real database.
    """

    def __init__(self):
        self.rules: tuple = ()
        self.registered: dict = {}
        self.logged: list = []
        self.replaced: dict = {}

    # -- the routes' read surface --------------------------------------
    FileRecord = FileRecord

    def file_by_id(self, file_id):
        return OWNER if file_id == OWNER.file_id else None

    def files_by_name(self, name):
        return (OWNER,) if name == OWNER.spyglass_name else ()

    def files_by_sha256(self, sha):
        return (OWNER,) if sha == OWNER.sha256 else ()

    def rules_for_file(self, file_id):
        return self.rules

    def usage_since(self, account_id, hours, action="read"):
        return Usage(0, None, frozenset())

    # -- the routes' write surface -------------------------------------
    def registration_for(self, sha256, name, owner):
        return self.registered.get((sha256, name, owner))

    def register_file(
        self, *, sha256, size_bytes, spyglass_name, file_class, owner, rules=()
    ):
        record = FileRecord(
            file_id=f"id{len(self.registered)}",
            sha256=sha256,
            size_bytes=size_bytes,
            spyglass_name=spyglass_name,
            file_class=file_class,
            owner=owner,
        )
        self.registered[(sha256, spyglass_name, owner)] = record
        return record

    def replace_rules(self, file_id, rules):
        self.replaced[file_id] = tuple(rules)

    def log_access(self, **kwargs):
        self.logged.append(kwargs)


@pytest.fixture
def reg():
    return _Registry()


@pytest.fixture
def client(store, reg):
    """The app, with every dependency supplied rather than patched."""
    app = create_app(
        verifier=_Verifier(),
        store=store,
        github=object(),
        registry_module=reg,
        settings=Settings(
            presigned_ttl_seconds=300,
            # Off here: the fake store holds no bytes, so a challenge over it
            # would prove nothing. Possession is covered in test_end_to_end
            # against a real store, where an answer means something.
            require_possession_proof=False,
        ),
    )

    return TestClient(app)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------- authentication ---------------------------


def test_missing_token_is_401(client, reg):
    """No credential is an authentication failure, not an authorization one."""
    reg.rules = ()
    r = client.get("/api/v1/file/resolve", params={"name": OWNER.spyglass_name})

    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_unknown_token_is_401(client, reg):
    """A token GitHub would reject never reaches a permission decision."""
    reg.rules = ()
    r = client.get(
        "/api/v1/file/resolve",
        params={"name": OWNER.spyglass_name},
        headers=auth("garbage"),
    )

    assert r.status_code == 401


# ------------------------------ resolve ------------------------------


def test_resolve_by_name_returns_the_contract_shape(client, reg):
    """Every required field of the contract's File schema is present."""
    reg.rules = ()
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
        "uploaded": True,
    }


def test_resolve_by_sha256(client, reg):
    reg.rules = ()
    r = client.get(
        "/api/v1/file/resolve",
        params={"sha256": SHA},
        headers=auth("owner"),
    )

    assert r.status_code == 200


def test_resolve_requires_a_selector(client, reg):
    """Neither name nor hash is a client error, not an empty result."""
    reg.rules = ()
    r = client.get("/api/v1/file/resolve", headers=auth("owner"))

    assert r.status_code == 422


def test_resolve_unknown_name_is_404(client, reg):
    reg.rules = ()
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
def test_read_permission_matrix(client, token, rules, expected, reg):
    reg.rules = (*rules,)
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth(token),
        follow_redirects=False,
    )

    assert r.status_code == expected


# ----------------------------- the redirect -----------------------------


def test_content_redirects_to_a_signed_url(client, store, reg):
    """302 to the object store, signed for the configured lifetime."""
    reg.rules = ()
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.status_code == 302
    assert r.headers["location"].startswith("https://objects.example.org/")
    assert store.presigned == [(object_key(SHA), 300)]


def test_redirect_is_not_cacheable(client, reg):
    """A cached 302 would replay a signature past its expiry.

    The stable URL only works because every request re-signs; caching it
    reintroduces exactly the expiry the design exists to avoid.
    """
    reg.rules = ()
    r = client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.headers["cache-control"] == "no-store"


def test_content_unknown_file_is_404(client, reg):
    reg.rules = ()
    r = client.get(
        "/api/v1/file/nosuch/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    assert r.status_code == 404


def test_denied_read_does_not_presign(client, store, reg):
    """A refused request must not mint a URL it then declines to return."""
    reg.rules = ()
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
    assert store.put_presigned == [(object_key("b" * 64), 300, "b" * 64)]


def test_register_deduplicates_existing_content(client, store):
    """Bytes already stored are not uploaded again.

    A duplicate hash reuses the existing object rather than storing it twice,
    which is the point of addressing objects by content.
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


# ----------------------------- visibility -----------------------------


@pytest.fixture
def vis_client(client):
    """Kept as a name for readability; the fake registry records the writes.

    It used to patch `replace_rules` onto the module. With the registry
    injected there is nothing left to patch.
    """
    return client


def test_owner_can_make_a_file_public(vis_client, reg):
    """S2: the owner widens access with no re-upload."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "public"},
        headers=auth("owner"),
    )

    assert r.status_code == 200
    assert reg.replaced[OWNER.file_id] == (AccessRule(Principal.PUBLIC),)


def test_owner_can_narrow_to_private(vis_client, reg):
    """Revoking is the case that has to be exact: no grants left behind."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "private"},
        headers=auth("owner"),
    )

    assert r.status_code == 200
    assert reg.replaced[OWNER.file_id] == ()


def test_owner_can_share_with_several_teams(vis_client, reg):
    """One file, several teams — what an enum on the file could not express."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "group", "teams": ["teamA", "teamB"]},
        headers=auth("owner"),
    )

    assert r.status_code == 200
    assert reg.replaced[OWNER.file_id] == (
        AccessRule(Principal.TEAM, "teamA"),
        AccessRule(Principal.TEAM, "teamB"),
    )


def test_a_reader_may_not_change_visibility(vis_client, reg):
    """Being able to read is not being able to re-share.

    The teammate can read this file once it is shared with teamA, but must
    not be able to widen it further.
    """
    reg.rules = AccessRule(
        Principal.TEAM,
        "teamA",
    )
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "public"},
        headers=auth("teammate"),
    )

    assert r.status_code == 403
    assert reg.replaced == {}


def test_stranger_may_not_change_visibility(vis_client):
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "public"},
        headers=auth("stranger"),
    )

    assert r.status_code == 403


def test_unregistered_may_not_change_visibility(vis_client):
    """An empty account id must never compare equal to an owner."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "public"},
        headers=auth("unregistered"),
    )

    assert r.status_code == 403


def test_visibility_on_unknown_file_is_404(vis_client):
    r = vis_client.patch(
        "/api/v1/file/nosuch/visibility",
        json={"scope": "public"},
        headers=auth("owner"),
    )

    assert r.status_code == 404


def test_group_without_teams_is_rejected(vis_client, reg):
    """Would silently mean private, which is not what the owner asked for."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "group", "teams": []},
        headers=auth("owner"),
    )

    assert r.status_code == 422
    assert reg.replaced == {}


# ----------------------------- access log -----------------------------


def test_granted_read_is_logged_with_its_size(client, reg):
    """Quota is charged when the URL is issued, so size rides on the grant."""
    reg.rules = ()
    client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("owner"),
        follow_redirects=False,
    )

    entry = reg.logged[-1]
    assert entry["action"] == "read"
    assert entry["granted"] is True
    assert entry["file_id"] == OWNER.file_id
    assert entry["size_bytes"] == OWNER.size_bytes


def test_refused_read_is_logged_and_charges_nothing(client, reg):
    """A refusal is the event an audit looks for, and transfers no bytes."""
    reg.rules = ()
    client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers=auth("stranger"),
        follow_redirects=False,
    )

    entry = reg.logged[-1]
    assert entry["granted"] is False
    assert entry["size_bytes"] == 0


def test_resolve_does_not_charge_quota(client, reg):
    """Resolving names a file; it does not hand out bytes."""
    reg.rules = ()
    client.get(
        "/api/v1/file/resolve",
        params={"name": OWNER.spyglass_name},
        headers=auth("owner"),
    )

    entry = reg.logged[-1]
    assert entry["action"] == "resolve"
    assert entry["size_bytes"] == 0


def test_refused_upload_is_logged(client, reg):
    """A tier that may not upload still leaves a trace."""
    client.post("/api/v1/file", json=BODY, headers=auth("unverified"))

    entry = reg.logged[-1]
    assert entry["action"] == "register"
    assert entry["granted"] is False


def test_refused_visibility_change_is_logged(vis_client, reg):
    """Attempting to re-share someone else's file is worth recording."""
    vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "public"},
        headers=auth("stranger"),
    )

    entry = reg.logged[-1]
    assert entry["action"] == "visibility"
    assert entry["granted"] is False
    assert entry["file_id"] == OWNER.file_id


def test_forwarded_ip_is_preferred_behind_a_proxy(client, reg):
    """Behind a proxy the peer address is the proxy, not the caller."""
    reg.rules = ()
    client.get(
        f"/api/v1/file/{OWNER.file_id}/content",
        headers={**auth("owner"), "X-Forwarded-For": "203.0.113.7, 10.0.0.1"},
        follow_redirects=False,
    )

    assert reg.logged[-1]["source_ip"] == "203.0.113.7"


def test_unauthenticated_request_is_not_logged_as_a_decision(client, reg):
    """401 never reached a permission decision, so there is none to record."""
    reg.rules = ()
    client.get(f"/api/v1/file/{OWNER.file_id}/content", follow_redirects=False)

    assert reg.logged == []


def test_healthz_needs_no_credential(client):
    """Something for a load balancer to poll, and it must not require auth."""
    r = client.get("/healthz")

    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_visibility_response_is_typed(vis_client):
    """The contract and the app agreed only by both being silent before."""
    r = vis_client.patch(
        f"/api/v1/file/{OWNER.file_id}/visibility",
        json={"scope": "group", "teams": ["teamA"]},
        headers=auth("owner"),
    )

    assert r.json() == {
        "file_id": OWNER.file_id,
        "scope": "group",
        "teams": ["teamA"],
    }
