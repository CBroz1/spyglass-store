"""The whole path: one person uploads a file, another streams it.

Nothing is faked below the HTTP client. Real MySQL, real MinIO, real broker
tokens, real signatures. The only stand-in is GitHub, because a test cannot
ask a human to approve a device code.

This is the test that would have caught every bug the unit suite could not:
a schema that will not declare, an adapter pointed at nothing, a signature the
store refuses, a redirect the client will not follow.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
from fastapi.testclient import TestClient

PAYLOAD = b"synthetic raw session bytes\n"
#: The real digest, not a placeholder. The store verifies the upload against
#: whatever hash was registered, so a stand-in value is rejected — which is
#: the point, and which these tests would otherwise paper over.
SHA = hashlib.sha256(PAYLOAD).hexdigest()
NAME = "minirec20230622_.nwb"


@pytest.fixture
def lab(lab_tables):
    """Two lab members: an owner and a teammate, both on teamA."""
    LabMember, LabTeam = lab_tables

    LabMember.insert([{"lab_member_name": "Ada L"}, {"lab_member_name": "Bob"}])
    LabMember.LabMemberInfo.insert(
        [
            {"lab_member_name": "Ada L", "github_user_name": "ada"},
            {"lab_member_name": "Bob", "github_user_name": "bob"},
        ]
    )
    LabTeam.insert1({"team_name": "teamA"})
    LabTeam.LabTeamMember.insert(
        [
            {"team_name": "teamA", "lab_member_name": "Ada L"},
            {"team_name": "teamA", "lab_member_name": "Bob"},
        ]
    )


@pytest.fixture
def accounts(db, broker_tables, lab):
    """Three registered identities, each with a broker token."""
    from spyglass_store import registry

    Account, _, _ = broker_tables
    tokens = {}

    for idx, (login, member, tier) in enumerate(
        [
            ("ada", "Ada L", "verified"),
            ("bob", "Bob", "verified"),
            ("mallory", None, "verified"),  # verified, but on no team
        ],
        start=1,
    ):
        Account.insert1(
            {
                "account_id": idx,
                "github_id": 1000 + idx,
                "github_login": login,
                "lab_member_name": member,
                "tier": tier,
                "github_created": "2015-01-01",
            }
        )
        tokens[login] = registry.issue_token(str(idx))

    return tokens


@pytest.fixture
def client(db, object_store, s3_settings, accounts):
    """The broker, wired to both containers and verifying real tokens."""
    from spyglass_store.app import create_app

    app = create_app(store=object_store, github=object(), settings=s3_settings)

    return TestClient(app)


def auth(tokens, who):
    return {"Authorization": f"Bearer {tokens[who]}"}


def test_upload_then_stream(client, accounts, object_store):
    """The whole story: Ada shares with teamA, Bob reads it.

    Neither ever holds an object-store credential, and the bytes never pass
    through the broker.
    """
    # 1. Ada registers the file, declaring it visible to her team.
    registered = client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
            "visibility": {"scope": "group", "teams": ["teamA"]},
        },
        headers=auth(accounts, "ada"),
    )

    assert registered.status_code == 201
    target = registered.json()
    assert target["deduplicated"] is False
    assert target["upload_url"], "new content needs somewhere to go"

    # 2. Ada uploads straight to the store. The broker is not in this path.
    httpx.put(
        target["upload_url"],
        content=PAYLOAD,
        headers=target["upload_headers"],
    ).raise_for_status()

    # 3. Bob, on the same team, finds it by name.
    resolved = client.get(
        "/api/v1/file/resolve",
        params={"name": NAME},
        headers=auth(accounts, "bob"),
    )

    assert resolved.status_code == 200
    file_id = resolved.json()["file_id"]

    # 4. Bob asks for the content and is redirected, not served.
    redirect = client.get(
        f"/api/v1/file/{file_id}/content",
        headers=auth(accounts, "bob"),
        follow_redirects=False,
    )

    assert redirect.status_code == 302
    assert redirect.headers["cache-control"] == "no-store"

    # 5. The signed URL yields the bytes Ada uploaded.
    streamed = httpx.get(redirect.headers["location"])

    assert streamed.status_code == 200
    assert streamed.content == PAYLOAD


def test_a_non_member_is_refused_the_same_file(client, accounts):
    """Mallory is verified and authenticated, and still gets nothing."""
    client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
            "visibility": {"scope": "group", "teams": ["teamA"]},
        },
        headers=auth(accounts, "ada"),
    )

    refused = client.get(
        "/api/v1/file/resolve",
        params={"name": NAME},
        headers=auth(accounts, "mallory"),
    )

    # 404, not 403: confirming the file exists would tell Mallory something
    # she has no right to know, and would stop her client trying elsewhere.
    assert refused.status_code == 404


def test_re_registering_the_same_bytes_skips_the_upload(client, accounts):
    """Dedup, end to end: the second registration gets no upload URL."""
    body = {
        "sha256": SHA,
        "size_bytes": len(PAYLOAD),
        "spyglass_name": NAME,
        "file_class": "raw",
    }

    first = client.post(
        "/api/v1/file", json=body, headers=auth(accounts, "ada")
    ).json()
    httpx.put(
        first["upload_url"],
        content=PAYLOAD,
        headers=first["upload_headers"],
    ).raise_for_status()

    # Bob registers the identical content under his own name.
    second = client.post(
        "/api/v1/file",
        json={**body, "spyglass_name": "bobs_copy_.nwb"},
        headers=auth(accounts, "bob"),
    ).json()

    assert second["deduplicated"] is True
    assert second["upload_url"] is None
    # A separate registration, so Bob owns his own row and visibility.
    assert second["file_id"] != first["file_id"]


def test_visibility_change_takes_effect_immediately(client, accounts):
    """Ada narrows to private; Bob loses access with no re-upload."""
    registered = client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
            "visibility": {"scope": "group", "teams": ["teamA"]},
        },
        headers=auth(accounts, "ada"),
    ).json()
    file_id = registered["file_id"]
    httpx.put(
        registered["upload_url"],
        content=PAYLOAD,
        headers=registered["upload_headers"],
    ).raise_for_status()

    before = client.get(
        f"/api/v1/file/{file_id}/content",
        headers=auth(accounts, "bob"),
        follow_redirects=False,
    )
    assert before.status_code == 302

    client.patch(
        f"/api/v1/file/{file_id}/visibility",
        json={"scope": "private"},
        headers=auth(accounts, "ada"),
    ).raise_for_status()

    after = client.get(
        f"/api/v1/file/{file_id}/content",
        headers=auth(accounts, "bob"),
        follow_redirects=False,
    )

    assert after.status_code == 403


def test_a_forged_token_gets_nothing(client, accounts):
    """The credential is checked against stored hashes, not trusted."""
    forged = client.get(
        "/api/v1/file/resolve",
        params={"name": NAME},
        headers={"Authorization": "Bearer definitely-not-a-real-token"},
    )

    assert forged.status_code == 401


def test_bytes_that_do_not_match_the_registered_hash_are_refused(
    client, accounts, object_store
):
    """Registering one hash and uploading other content must not work.

    The broker never sees the bytes, so it cannot check this itself. It signs
    the declared hash into the upload URL and the store enforces it — and
    because the requirement is part of the signature, a client cannot drop the
    header to skip the check.
    """
    target = client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
        },
        headers=auth(accounts, "ada"),
    ).json()

    wrong = httpx.put(
        target["upload_url"],
        content=b"entirely different content",
        headers=target["upload_headers"],
    )

    assert wrong.status_code == 400
    assert "ChecksumMismatch" in wrong.text
    assert not object_store.exists(target["upload_url"].split("?")[0][-64:])


def test_the_checksum_header_cannot_be_dropped(client, accounts):
    """Omitting the header invalidates the signature rather than waiving it."""
    target = client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
        },
        headers=auth(accounts, "ada"),
    ).json()

    assert target["upload_headers"], "the broker must state the requirement"

    bare = httpx.put(target["upload_url"], content=PAYLOAD)

    assert bare.status_code >= 400


def test_a_registration_awaiting_bytes_is_not_an_error(client, accounts):
    """Someone else's upload in progress is a state, not a failure.

    Uploads are expected to be slow, so a registered file whose bytes have not
    arrived is normal. Saying "not found" would make a teammate think the
    share failed; 409 says the declaration is real and the data is coming.
    """
    registered = client.post(
        "/api/v1/file",
        json={
            "sha256": SHA,
            "size_bytes": len(PAYLOAD),
            "spyglass_name": NAME,
            "file_class": "raw",
            "visibility": {"scope": "group", "teams": ["teamA"]},
        },
        headers=auth(accounts, "ada"),
    ).json()

    # Bob can see it exists and that it is not ready.
    resolved = client.get(
        "/api/v1/file/resolve",
        params={"name": NAME},
        headers=auth(accounts, "bob"),
    )

    assert resolved.status_code == 200
    assert resolved.json()["uploaded"] is False

    pending = client.get(
        f"/api/v1/file/{registered['file_id']}/content",
        headers=auth(accounts, "bob"),
        follow_redirects=False,
    )

    assert pending.status_code == 409

    # Once Ada uploads, the same request succeeds with no further declaration.
    httpx.put(
        registered["upload_url"],
        content=PAYLOAD,
        headers=registered["upload_headers"],
    ).raise_for_status()

    ready = client.get(
        f"/api/v1/file/{registered['file_id']}/content",
        headers=auth(accounts, "bob"),
        follow_redirects=False,
    )

    assert ready.status_code == 302


def test_resolve_prefers_the_callers_own_registration(client, accounts):
    """Two declarations about one file; each caller gets their own.

    A Spyglass name is a primary key, so both rows describe the same content.
    They differ in who owns them and who may read them.
    """
    body = {
        "sha256": SHA,
        "size_bytes": len(PAYLOAD),
        "spyglass_name": NAME,
        "file_class": "raw",
    }

    ada = client.post(
        "/api/v1/file", json=body, headers=auth(accounts, "ada")
    ).json()
    bob = client.post(
        "/api/v1/file", json=body, headers=auth(accounts, "bob")
    ).json()

    assert ada["file_id"] != bob["file_id"]

    for who, expected in (("ada", ada), ("bob", bob)):
        got = client.get(
            "/api/v1/file/resolve",
            params={"name": NAME},
            headers=auth(accounts, who),
        )
        assert got.json()["file_id"] == expected["file_id"]
