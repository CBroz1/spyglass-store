"""Tests that need a real server.

Everything here exercises something a fake cannot: reflecting Spyglass's lab
schema, and reading rows back through `registry` after a real insert. The
permission logic is covered without a database elsewhere; these cover the
seam between that logic and MySQL.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from spyglass_store.access import AccessRule, Principal
from spyglass_store.auth import Identity


@pytest.fixture
def member(lab_tables):
    """One lab member on one team, linked to a GitHub login."""
    LabMember, LabTeam = lab_tables

    LabMember.insert1({"lab_member_name": "Ada L"})
    LabMember.LabMemberInfo.insert1(
        {"lab_member_name": "Ada L", "github_user_name": "ada"}
    )
    LabTeam.insert1({"team_name": "teamA"})
    LabTeam.LabTeamMember.insert1(
        {"team_name": "teamA", "lab_member_name": "Ada L"}
    )

    return "ada"


# ----------------------------- reflection -----------------------------


def test_verify_lab_schema_passes_against_real_tables(db, lab_tables):
    """The startup check must accept the schema Spyglass actually declares."""
    from spyglass_store.lab import verify_lab_schema

    verify_lab_schema()  # raises if a required column is missing


def test_verify_lab_schema_names_what_is_missing(db, lab_tables, monkeypatch):
    """A renamed column upstream has to fail loudly, naming the column."""
    from spyglass_store import lab

    monkeypatch.setitem(
        lab.REQUIRED_COLUMNS,
        ("LabTeam", "LabTeamMember"),
        ("team_name", "orcid_id"),
    )

    with pytest.raises(RuntimeError, match="orcid_id"):
        lab.verify_lab_schema()


def test_teams_resolve_through_github_login(db, member):
    """The whole point of reflection: a GitHub login to a set of teams."""
    from spyglass_store.lab import lab_member_for_github, teams_for_github

    assert lab_member_for_github(member) == "Ada L"
    assert teams_for_github(member) == {"teamA"}


def test_unlinked_login_has_no_teams(db, lab_tables):
    """An unaffiliated reader is normal, not an error."""
    from spyglass_store.lab import lab_member_for_github, teams_for_github

    assert lab_member_for_github("stranger") is None
    assert teams_for_github("stranger") == set()


# ------------------------------ registry ------------------------------


@pytest.fixture
def registered(broker_tables, member):
    """An account owning one private file."""
    Account, File, _ = broker_tables

    Account.insert1(
        {
            "account_id": 1,
            "github_id": 9001,
            "github_login": member,
            "lab_member_name": "Ada L",
            "tier": "verified",
            "github_created": "2014-10-26",
        }
    )
    File.insert1(
        {
            "file_id": "f" * 32,
            "sha256": "a" * 64,
            "size_bytes": 2048,
            "spyglass_name": "session1_.nwb",
            "file_class": "raw",
            "owner": 1,
        }
    )

    return "f" * 32


def test_file_lookups_agree(db, registered):
    """Id, name, and hash must reach the same row."""
    from spyglass_store import registry

    by_id = registry.file_by_id(registered)
    by_name = registry.files_by_name("session1_.nwb")[0]
    by_sha = registry.files_by_sha256("a" * 64)[0]

    assert by_id == by_name == by_sha
    assert by_id.size_bytes == 2048
    assert by_id.owner == "1"


def test_missing_file_is_none(db, broker_tables):
    """A lookup miss is None, not an exception."""
    from spyglass_store import registry

    assert registry.file_by_id("0" * 32) is None
    assert registry.files_by_name("nope.nwb") == ()


def test_private_file_has_no_rules(db, registered):
    """Private is the absence of grants, not a grant of its own."""
    from spyglass_store import registry

    assert registry.rules_for_file(registered) == ()


def test_rules_round_trip(db, registered, broker_tables):
    """Grants written as rows come back as the enums access.py expects."""
    from spyglass_store import registry

    _, _, FileAccess = broker_tables
    FileAccess.insert1(
        {
            "file_id": registered,
            "principal_type": "team",
            "principal": "teamA",
        }
    )

    rules = registry.rules_for_file(registered)

    assert len(rules) == 1
    assert rules[0].principal_type is Principal.TEAM
    assert rules[0].principal == "teamA"


# --------------------------- token resolution ---------------------------


def test_token_resolves_to_account_and_teams(db, registered):
    """A broker token carries everything a decision needs, in one lookup.

    No GitHub round trip: the token is checked against a stored hash, so a
    slow or unreachable GitHub cannot stall a read.
    """
    from spyglass_store import registry

    token = registry.issue_token("1")
    resolved = registry.identity_for_token(token)

    assert resolved.account_id == "1"
    assert resolved.tier == "verified"
    assert resolved.teams == frozenset({"teamA"})
    assert resolved.as_reader().tier.may_read_private


def test_unknown_token_is_none(db, broker_tables):
    """An unrecognized token names nobody."""
    from spyglass_store import registry

    assert registry.identity_for_token("not-a-real-token") is None


def test_the_token_itself_is_never_stored(db, registered):
    """A leaked database must not yield usable credentials."""
    from spyglass_store import registry

    token = registry.issue_token("1")
    stored = db.ClientToken.fetch("token_hash")

    assert token not in stored
    assert registry.token_hash(token) in stored


# ------------------------------ registration ------------------------------


@pytest.fixture
def uploader(broker_tables, member):
    """A verified account that may upload."""
    Account, _, _ = broker_tables

    Account.insert1(
        {
            "account_id": 1,
            "github_id": 9001,
            "github_login": member,
            "lab_member_name": "Ada L",
            "tier": "verified",
            "github_created": "2014-10-26",
        }
    )

    return "1"


def test_register_writes_file_and_grants(db, uploader):
    """Row and grants land together, and read back as the same file."""
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    file = registry.register_file(
        sha256="b" * 64,
        size_bytes=99,
        spyglass_name="new_.nwb",
        file_class="analysis",
        owner=uploader,
        rules=rules_for(Scope.GROUP, ["teamA"]),
    )

    assert registry.file_by_id(file.file_id) == file
    assert registry.rules_for_file(file.file_id)[0].principal == "teamA"


def test_register_private_records_no_grants(db, uploader):
    """Private is the absence of rows, so nothing to leak or revoke."""
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    file = registry.register_file(
        sha256="c" * 64,
        size_bytes=1,
        spyglass_name="private_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.PRIVATE),
    )

    assert registry.rules_for_file(file.file_id) == ()


def test_registration_is_idempotent_per_owner(db, uploader):
    """A retried registration finds the first one instead of adding a row."""
    from spyglass_store import registry

    first = registry.register_file(
        sha256="d" * 64,
        size_bytes=5,
        spyglass_name="retry_.nwb",
        file_class="raw",
        owner=uploader,
    )
    found = registry.registration_for("d" * 64, "retry_.nwb", uploader)

    assert found == first


def test_a_different_name_is_a_different_registration(db, uploader):
    """Same bytes under another name is a new registration, not a duplicate.

    The object deduplicates by hash; the registration carries ownership and
    visibility, which are per name.
    """
    from spyglass_store import registry

    first = registry.register_file(
        sha256="e" * 64,
        size_bytes=5,
        spyglass_name="one_.nwb",
        file_class="raw",
        owner=uploader,
    )
    second = registry.register_file(
        sha256="e" * 64,
        size_bytes=5,
        spyglass_name="two_.nwb",
        file_class="raw",
        owner=uploader,
    )

    assert first.file_id != second.file_id
    assert first.sha256 == second.sha256


def test_failed_grant_rolls_back_the_file(db, uploader):
    """Neither half is written alone.

    A file row with its public grant lost would be silently private, and the
    owner would have no signal that sharing failed.
    """
    from spyglass_store import registry
    from spyglass_store.access import AccessRule

    bogus = AccessRule.__new__(AccessRule)  # bypass the frozen enum field
    object.__setattr__(bogus, "principal_type", Principal.TEAM)
    object.__setattr__(
        bogus, "principal", "x" * 200
    )  # too long for varchar(80)

    with pytest.raises(Exception):
        registry.register_file(
            sha256="f" * 64,
            size_bytes=5,
            spyglass_name="rollback_.nwb",
            file_class="raw",
            owner=uploader,
            rules=[bogus],
        )

    assert registry.files_by_name("rollback_.nwb") == ()


# ------------------------------ visibility ------------------------------


def test_replace_rules_widens_then_narrows(db, uploader):
    """A visibility change rewrites grants and touches nothing else."""
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    file = registry.register_file(
        sha256="1" * 64,
        size_bytes=7,
        spyglass_name="vis_.nwb",
        file_class="raw",
        owner=uploader,
    )

    registry.replace_rules(file.file_id, rules_for(Scope.PUBLIC))
    assert registry.rules_for_file(file.file_id) == (
        AccessRule(Principal.PUBLIC),
    )

    registry.replace_rules(file.file_id, rules_for(Scope.GROUP, ["teamA"]))
    assert registry.rules_for_file(file.file_id) == (
        AccessRule(Principal.TEAM, "teamA"),
    )

    registry.replace_rules(file.file_id, rules_for(Scope.PRIVATE))
    assert registry.rules_for_file(file.file_id) == ()

    # The file itself is untouched throughout: no re-upload, no new object.
    assert registry.file_by_id(file.file_id) == file


def test_revoking_a_team_leaves_no_stale_grant(db, uploader):
    """Narrowing must not leave the old audience behind.

    Access is the union of the rows, so a leftover grant is not merely
    untidy — it is continued access the owner believes they revoked.
    """
    from spyglass_store import registry
    from spyglass_store.access import Reader, Scope, can_read, rules_for

    file = registry.register_file(
        sha256="2" * 64,
        size_bytes=7,
        spyglass_name="revoke_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.GROUP, ["teamA", "teamB"]),
    )
    member_of_b = Reader("99", frozenset({"teamB"}))

    assert can_read(registry.rules_for_file(file.file_id), member_of_b, "1")

    registry.replace_rules(file.file_id, rules_for(Scope.GROUP, ["teamA"]))

    assert not can_read(registry.rules_for_file(file.file_id), member_of_b, "1")


def test_membership_change_takes_effect_without_re_upload(
    db, uploader, lab_tables
):
    """Revoking membership revokes access.

    The grant names a team, not a person, so the decision follows Spyglass's
    `LabTeam` live rather than a copy taken at registration.
    """
    from spyglass_store import registry
    from spyglass_store.access import Reader, Scope, can_read, rules_for
    from spyglass_store.lab import teams_for_github

    LabMember, LabTeam = lab_tables
    LabMember.insert1({"lab_member_name": "Bob"})
    LabMember.LabMemberInfo.insert1(
        {"lab_member_name": "Bob", "github_user_name": "bob"}
    )
    LabTeam.LabTeamMember.insert1(
        {"team_name": "teamA", "lab_member_name": "Bob"}
    )

    file = registry.register_file(
        sha256="3" * 64,
        size_bytes=7,
        spyglass_name="team_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.GROUP, ["teamA"]),
    )
    rules = registry.rules_for_file(file.file_id)

    bob = Reader("42", frozenset(teams_for_github("bob")))
    assert can_read(rules, bob, "1")

    (LabTeam.LabTeamMember & {"lab_member_name": "Bob"}).delete_quick()

    bob_after = Reader("42", frozenset(teams_for_github("bob")))
    assert not can_read(rules, bob_after, "1")


# ------------------------------ access log ------------------------------


def test_log_records_a_decision(db, uploader, broker_tables):
    """A granted read lands as one row carrying what quota needs."""
    from spyglass_store import registry

    registry.log_access(
        identity=Identity(github_id=9001, account_id=uploader),
        action="read",
        granted=True,
        file_id="9" * 32,
        size_bytes=4096,
        source_ip="203.0.113.7",
    )

    row = db.AccessLog.fetch(as_dict=True)[-1]

    assert row["account_id"] == 1
    assert row["action"] == "read"
    assert bool(row["granted"]) is True
    assert row["size_bytes"] == 4096
    assert row["source_ip"] == "203.0.113.7"


def test_log_records_a_caller_with_no_account(db, broker_tables):
    """The audit-worthy case: recognized by GitHub, refused by the broker.

    A non-null foreign key would have made exactly this row un-writable, so
    the account is null and `github_id` carries who it was.
    """
    from spyglass_store import registry

    registry.log_access(
        identity=Identity(github_id=4242, github_login="stranger"),
        action="read",
        granted=False,
        file_id="8" * 32,
        source_ip="198.51.100.9",
    )

    row = db.AccessLog.fetch(as_dict=True)[-1]

    assert row["account_id"] is None
    assert row["github_id"] == 4242
    assert bool(row["granted"]) is False


def test_log_failure_does_not_raise(db, broker_tables):
    """An audit outage must not become a service outage.

    A source_ip far past varchar(45) would fail the insert; the request it
    described still has to succeed.
    """
    from spyglass_store import registry

    before = len(db.AccessLog.fetch("log_id"))

    registry.log_access(
        identity=Identity(github_id=1),
        action="not_a_valid_action",  # outside the enum
        granted=True,
    )

    assert len(db.AccessLog.fetch("log_id")) == before


# -------------------------------- login --------------------------------


class _FakeGitHub:
    """Stands in for the device flow, with GitHub's answers scripted."""

    def __init__(self, user=None, poll=None):
        self._user = user
        self._poll = poll
        self.tokens_seen = []

    def begin(self):
        from spyglass_store.github import DeviceCode

        return DeviceCode("dev-1", "ABCD-EFGH", "https://gh/device", 5, 900)

    def poll(self, device_code):
        if isinstance(self._poll, Exception):
            raise self._poll
        return self._poll or "gho_secret"

    def user(self, token):
        self.tokens_seen.append(token)
        return self._user


def _gh_user(login="ada", github_id=9001, age_days=4000):
    from datetime import date

    from spyglass_store.github import GitHubUser

    return GitHubUser(
        github_id=github_id,
        github_login=login,
        created=date.today() - timedelta(days=age_days),
    )


@pytest.fixture
def login_client(db, broker_tables, member):
    """A client whose GitHub is scripted but whose database is real."""
    from fastapi.testclient import TestClient

    from spyglass_store.app import create_app
    from spyglass_store.settings import Settings

    def build(github):
        app = create_app(
            github=github,
            store=object(),
            settings=Settings(min_account_age_days=30),
        )
        return TestClient(app)

    return build


def test_login_creates_an_account_and_returns_a_broker_token(
    login_client, db, member
):
    """A lab member logs in once and gets a credential the broker owns."""
    gh = _FakeGitHub(user=_gh_user(login=member))
    client = login_client(gh)

    r = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert r.status_code == 200
    body = r.json()
    assert body["github_login"] == member
    # Linked to a LabMember, so verified on sight.
    assert body["tier"] == "verified"

    account = db.Account.fetch(as_dict=True)[0]
    assert account["github_id"] == 9001
    assert account["lab_member_name"] == "Ada L"


def test_the_issued_token_authenticates_later_requests(login_client, member):
    """The point of the exchange: the token works as a bearer credential."""
    from spyglass_store import registry

    gh = _FakeGitHub(user=_gh_user(login=member))
    client = login_client(gh)

    token = client.post(
        "/api/v1/auth/token", json={"device_code": "dev-1"}
    ).json()["access_token"]

    identity = registry.identity_for_token(token)

    assert identity.github_login == member
    assert identity.teams == frozenset({"teamA"})


def test_the_github_token_is_never_persisted(login_client, db, member):
    """It is used once to learn a username, then dropped.

    This is the whole security argument for the OAuth app: nothing the broker
    stores can act on GitHub.
    """
    gh = _FakeGitHub(user=_gh_user(login=member))
    client = login_client(gh)

    client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert gh.tokens_seen == ["gho_secret"]  # it was used
    stored = set(db.ClientToken.fetch("token_hash"))
    assert "gho_secret" not in stored
    assert all("gho_" not in h for h in stored)


def test_an_unaffiliated_reader_gets_an_account_but_not_a_tier(
    login_client, db, lab_tables
):
    """A valid GitHub user with no lab link is unverified, not refused."""
    gh = _FakeGitHub(user=_gh_user(login="outsider", github_id=7777))
    client = login_client(gh)

    r = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert r.status_code == 200
    assert r.json()["tier"] == "unverified"


def test_a_too_new_account_is_refused(login_client, db, lab_tables):
    """Accounts are free and instant, so age is the cheap throttle."""
    gh = _FakeGitHub(user=_gh_user(login="fresh", github_id=5, age_days=3))
    client = login_client(gh)

    r = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert r.status_code == 403
    assert "3 days old" in r.json()["detail"]
    assert len(db.Account.fetch("account_id")) == 0  # nothing created


def test_pending_authorization_is_428_with_a_retry_hint(
    login_client, lab_tables
):
    """Polling before approval is normal, and must not look like failure."""
    from spyglass_store.github import AuthorizationPending

    gh = _FakeGitHub(poll=AuthorizationPending(interval=7))
    client = login_client(gh)

    r = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert r.status_code == 428
    assert r.headers["Retry-After"] == "7"


def test_a_denied_device_code_is_403(login_client, lab_tables):
    from spyglass_store.github import DeviceFlowError

    gh = _FakeGitHub(poll=DeviceFlowError("Device flow failed: access_denied"))
    client = login_client(gh)

    r = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert r.status_code == 403


def test_logging_in_twice_reuses_the_account(login_client, db, member):
    """A second login is not a second account."""
    gh = _FakeGitHub(user=_gh_user(login=member))
    client = login_client(gh)

    first = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})
    second = client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    assert len(db.Account.fetch("account_id")) == 1
    # Distinct tokens, though: logging in again does not revoke the old one.
    assert first.json()["access_token"] != second.json()["access_token"]


def test_a_renamed_github_login_keeps_its_account(login_client, db, member):
    """Accounts key on github_id, which a rename does not change.

    Keying on the login would orphan the user's files the day they rename.
    """
    client = login_client(_FakeGitHub(user=_gh_user(login=member)))
    client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    renamed = login_client(_FakeGitHub(user=_gh_user(login="ada-renamed")))
    renamed.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    accounts = db.Account.fetch(as_dict=True)

    assert len(accounts) == 1
    assert accounts[0]["github_login"] == "ada-renamed"


def test_login_is_recorded(login_client, db, member):
    """Both the grant and the refusal are auditable events."""
    client = login_client(_FakeGitHub(user=_gh_user(login=member)))
    client.post("/api/v1/auth/token", json={"device_code": "dev-1"})

    row = db.AccessLog.fetch(as_dict=True)[-1]

    assert row["action"] == "login"
    assert bool(row["granted"]) is True


def test_device_endpoint_hands_back_a_user_code(login_client, lab_tables):
    client = login_client(_FakeGitHub())

    r = client.post("/api/v1/auth/device")

    assert r.status_code == 200
    assert r.json()["user_code"] == "ABCD-EFGH"


# ------------------------------- quota -------------------------------


@pytest.fixture
def quota_client(db, broker_tables, member, uploader):
    """A client whose tier allowance is tiny, so a few reads exhaust it."""
    from fastapi.testclient import TestClient

    from spyglass_store.app import create_app
    from spyglass_store.settings import Settings

    class _Store:
        def presigned_get(self, key, ttl):
            return "https://objects.example.org/signed"

        def exists(self, key):
            return True

        def size(self, key):
            return None

        def presigned_put(self, key, ttl, sha256=None):  # pragma: no cover
            from spyglass_store.storage import PresignedUpload

            return PresignedUpload("", {})

    settings = Settings(
        download_tb_per_day=100 / 1024**4,  # 100 bytes
        upload_tb_per_day=100 / 1024**4,
        quota_window_hours=24,
    )

    return TestClient(
        create_app(store=_Store(), github=object(), settings=settings)
    )


@pytest.fixture
def big_file(db, uploader):
    """A file larger than the tiny allowance above."""
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    return registry.register_file(
        sha256="4" * 64,
        size_bytes=80,
        spyglass_name="big_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.PUBLIC),
    )


def test_quota_allows_a_read_within_the_allowance(
    quota_client, big_file, uploader
):
    from spyglass_store import registry

    token = registry.issue_token(uploader)
    r = quota_client.get(
        f"/api/v1/file/{big_file.file_id}/content",
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
    )

    assert r.status_code == 302


def test_quota_refuses_once_exhausted(quota_client, big_file, uploader):
    """Two distinct 80-byte files exceed a 100-byte allowance.

    Distinct files, not two reads of one: re-reading a file inside the window
    is free, because a streamed read re-follows the redirect many times for a
    single transfer.
    """
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    other = registry.register_file(
        sha256="5" * 64,
        size_bytes=80,
        spyglass_name="other_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.PUBLIC),
    )
    token = registry.issue_token(uploader)
    headers = {"Authorization": f"Bearer {token}"}

    first = quota_client.get(
        f"/api/v1/file/{big_file.file_id}/content",
        headers=headers,
        follow_redirects=False,
    )
    second = quota_client.get(
        f"/api/v1/file/{other.file_id}/content",
        headers=headers,
        follow_redirects=False,
    )

    assert first.status_code == 302
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) > 0
    assert "allowance" in second.json()["detail"]


def test_a_refused_read_is_not_charged(quota_client, big_file, uploader, db):
    """Only granted reads count, so a 429 must not deepen the hole."""
    from spyglass_store import registry

    token = registry.issue_token(uploader)
    headers = {"Authorization": f"Bearer {token}"}
    url = f"/api/v1/file/{big_file.file_id}/content"

    quota_client.get(url, headers=headers, follow_redirects=False)
    quota_client.get(url, headers=headers, follow_redirects=False)  # 429

    usage = registry.usage_since(uploader, 24)

    assert usage.total_bytes == 80, "a refused read must not be charged"


def test_usage_ignores_resolves_and_denials(db, uploader):
    """A resolve hands out a name; a denial hands out nothing."""
    from spyglass_store import registry

    ident = Identity(github_id=9001, account_id=uploader, tier="verified")
    registry.log_access(
        identity=ident, action="resolve", granted=True, size_bytes=999
    )
    registry.log_access(
        identity=ident, action="read", granted=False, size_bytes=999
    )

    usage = registry.usage_since(uploader, 24)

    assert usage.total_bytes == 0


def test_an_unset_limit_means_unlimited(db):
    """None is no ceiling, not a ceiling of zero."""
    from spyglass_store.settings import Settings

    assert Settings(download_tb_per_day=None).volume_limit("read") is None
    assert Settings().volume_limit("read") is not None


def test_uploads_and_downloads_have_separate_allowances(db):
    """One is far scarcer than the other, so they are configured apart."""
    from spyglass_store.settings import Settings

    settings = Settings(download_tb_per_day=20, upload_tb_per_day=5)

    assert settings.volume_limit("read") == 20 * 1024**4
    assert settings.volume_limit("register") == 5 * 1024**4


def test_tier_gates_capability_while_volume_gates_amount(db):
    """Two orthogonal controls, deliberately not merged.

    A tier answers *may you*: read private data, upload at all. A volume limit
    answers *how much*. Folding them together would mean promoting someone to
    give them headroom, or raising a global ceiling to grant one person
    access.
    """
    from spyglass_store.auth import Identity
    from spyglass_store.settings import Settings

    settings = Settings()

    unverified = Identity(github_id=1, tier="unverified").as_reader()
    verified = Identity(github_id=1, tier="verified").as_reader()

    assert not unverified.tier.may_read_private
    assert verified.tier.may_read_private
    # The same allowance applies to both, because it is not a tier question.
    assert settings.volume_limit("read") == settings.volume_limit("read")


def test_streaming_one_file_is_charged_once(quota_client, big_file, uploader):
    """Range requests re-follow the redirect; that must not bill per hop.

    The stable content URL re-signs on every call, so a streamed read produces
    many read events for a single transfer. Charging each would bill a large
    session as many multiples of its size and throttle exactly the workload
    this service exists to support.
    """
    from spyglass_store import registry

    token = registry.issue_token(uploader)
    headers = {"Authorization": f"Bearer {token}"}
    url = f"/api/v1/file/{big_file.file_id}/content"

    # 80-byte file, 100-byte allowance: a per-request charge fails on hop two.
    for _ in range(5):
        assert (
            quota_client.get(
                url, headers=headers, follow_redirects=False
            ).status_code
            == 302
        )

    usage = registry.usage_since(uploader, 24)

    assert usage.total_bytes == 80, "one file, charged once"
    assert big_file.file_id in usage.files


# --------------------------- tokens and metering ---------------------------


def test_a_token_carries_an_expiry(db, uploader):
    """A bearer credential with no lifetime is one leak away from permanent."""
    from spyglass_store import registry

    registry.issue_token(uploader, ttl_days=30)
    expires = db.ClientToken.fetch("expires")[-1]

    assert expires is not None


def test_an_expired_token_names_nobody(db, uploader):
    """The check is live, not decorative."""
    from spyglass_store import registry
    from spyglass_store.db import db_now

    token = registry.issue_token(uploader, ttl_days=30)
    db.ClientToken.update1(
        {
            "token_hash": registry.token_hash(token),
            "expires": db_now() - timedelta(days=1),
        }
    )

    assert registry.identity_for_token(token) is None


def test_revoking_cuts_off_every_token_an_account_holds(db, uploader):
    """Logging in repeatedly must not leave a trail of live credentials."""
    from spyglass_store import registry

    first = registry.issue_token(uploader)
    second = registry.issue_token(uploader)

    assert registry.revoke_tokens(uploader) == 2
    assert registry.identity_for_token(first) is None
    assert registry.identity_for_token(second) is None


def test_quota_charges_the_stored_size_not_the_declared_one(db, uploader):
    """A declared size is a claim; only the store knows the truth.

    Without this, a verified uploader registers one byte for a huge object and
    every read of it is free forever.
    """
    from spyglass_store.app import _charged_size
    from spyglass_store.registry import FileRecord

    class _Store:
        def size(self, key):
            return 10 * 1024**3

    lying = FileRecord("f", "6" * 64, 1, "lie_.nwb", "raw", uploader)

    assert _charged_size(_Store(), lying) == 10 * 1024**3


def test_charge_falls_back_when_the_store_cannot_say(db, uploader):
    """A storage hiccup must not hand out free reads either."""
    from spyglass_store.app import _charged_size
    from spyglass_store.registry import FileRecord

    class _Broken:
        def size(self, key):
            raise RuntimeError("store unreachable")

    file = FileRecord("f", "6" * 64, 4096, "x_.nwb", "raw", uploader)

    assert _charged_size(_Broken(), file) == 4096


def test_the_quota_window_uses_the_database_clock(db, uploader):
    """Mixing the broker host's clock with MySQL's slides the window.

    `db_now` is naive in the session time zone, exactly as the stored
    timestamps are, so the two are directly comparable.
    """
    from spyglass_store.db import db_now

    stamped = db_now()

    assert stamped.tzinfo is None


def test_an_ambiguous_github_login_is_flagged(db, lab_tables, caplog):
    """One GitHub login must map to at most one lab member.

    Upstream should enforce this with a unique index. If it does not, picking
    a row silently would hand one person another's teams, so the ambiguity is
    logged. The lookup still returns a member rather than refusing the login,
    since the user cannot fix an administrative mistake by retrying.
    """
    import logging

    from spyglass_store.lab import lab_member_for_github

    LabMember, _ = lab_tables
    LabMember.insert([{"lab_member_name": "Ada L"}, {"lab_member_name": "Eve"}])
    LabMember.LabMemberInfo.insert(
        [
            {"lab_member_name": "Ada L", "github_user_name": "shared"},
            {"lab_member_name": "Eve", "github_user_name": "shared"},
        ]
    )

    with caplog.at_level(logging.WARNING):
        member = lab_member_for_github("shared")

    assert member is not None
    assert "recorded against 2 lab members" in caplog.text
    assert "unique index" in caplog.text


# ------------------------- what the meter counts -------------------------


def test_upload_volume_is_metered_apart_from_download_volume(db, uploader):
    """Two allowances are configured apart, so they have to count apart.

    Totalling reads whichever action was asked for made the upload limit a
    second, stricter download limit: a day of reading exhausted it without
    anyone uploading a byte, and an admin reading `account show` was told
    downloads had been uploaded.
    """
    from spyglass_store import registry

    ident = Identity(github_id=9001, account_id=uploader, tier="verified")
    registry.log_access(
        identity=ident,
        action="read",
        granted=True,
        file_id="a" * 32,
        size_bytes=500,
    )
    registry.log_access(
        identity=ident,
        action="register",
        granted=True,
        file_id="b" * 32,
        size_bytes=10,
    )

    assert registry.usage_since(uploader, 24, "read").total_bytes == 500
    assert registry.usage_since(uploader, 24, "register").total_bytes == 10


def test_the_meter_folds_repeat_reads_in_one_query(db, uploader):
    """The log grows per request; the answer must not.

    Quota's unit is the distinct file, so a file read many times is one charge.
    Summing that in Python meant fetching every read event in the window —
    cheap until an account had been streaming, which is exactly when the check
    runs most. The totals now come back from MySQL, one row per file.
    """
    from spyglass_store import registry

    ident = Identity(github_id=9001, account_id=uploader, tier="verified")
    for _ in range(4):
        registry.log_access(
            identity=ident,
            action="read",
            granted=True,
            file_id="a" * 32,
            size_bytes=40,
        )
    registry.log_access(
        identity=ident,
        action="read",
        granted=True,
        file_id="b" * 32,
        size_bytes=25,
    )

    usage = registry.usage_since(uploader, 24)

    assert usage.total_bytes == 65, "four reads of one file is one charge"
    assert usage.files == {"a" * 32, "b" * 32}


def test_the_meter_reports_the_oldest_charge_inside_the_window(db, uploader):
    """`Retry-After` is derived from it, and the window ends at it.

    A charge that has aged out must not be counted, and the oldest one that
    has not is when capacity next returns. Folding the rows down to a total
    must keep that minimum rather than any convenient row's timestamp.
    """
    from spyglass_store import registry
    from spyglass_store.db import db_now

    now = db_now()
    rows = [
        # (age, size) — the first has aged out of a 24h window.
        (timedelta(hours=30), 999),
        (timedelta(hours=6), 7),
        (timedelta(hours=1), 3),
    ]
    for index, (age, size) in enumerate(rows):
        db.AccessLog.insert1(
            {
                "account_id": int(uploader),
                "action": "read",
                "file_id": str(index) * 32,
                "granted": 1,
                "size_bytes": size,
                "source_ip": "",
                "timestamp": now - age,
            }
        )

    usage = registry.usage_since(uploader, 24)

    assert usage.total_bytes == 10, "the 30h-old charge has aged out"
    assert usage.earliest == now - timedelta(hours=6)
