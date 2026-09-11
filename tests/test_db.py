"""Tests that need a real server.

Everything here exercises something a fake cannot: reflecting Spyglass's lab
schema, and reading rows back through `registry` after a real insert. The
permission logic is covered without a database elsewhere; these cover the
seam between that logic and MySQL.
"""

from __future__ import annotations

import pytest

from spyglass_store.access import Principal
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
    by_name = registry.file_by_name("session1_.nwb")
    by_sha = registry.file_by_sha256("a" * 64)

    assert by_id == by_name == by_sha
    assert by_id.size_bytes == 2048
    assert by_id.owner == "1"


def test_missing_file_is_none(db, broker_tables):
    """A lookup miss is None, not an exception."""
    from spyglass_store import registry

    assert registry.file_by_id("0" * 32) is None
    assert registry.file_by_name("nope.nwb") is None


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


# --------------------------- account resolution ---------------------------


def test_resolve_account_fills_in_teams(db, registered):
    """A known GitHub id gains its account, tier, and teams in one step."""
    from spyglass_store import registry

    resolved = registry.resolve_account(Identity(github_id=9001))

    assert resolved.account_id == "1"
    assert resolved.tier == "verified"
    assert resolved.teams == frozenset({"teamA"})
    assert resolved.may_read_private


def test_unknown_github_id_stays_unregistered(db, broker_tables):
    """Authenticated but unregistered: no account, no teams, public only.

    The read path creates nothing, so an unknown caller must degrade to the
    unverified tier rather than being invented as an account.
    """
    from spyglass_store import registry

    resolved = registry.resolve_account(
        Identity(github_id=404, github_login="x")
    )

    assert resolved.account_id == ""
    assert resolved.tier == "unverified"
    assert resolved.teams == frozenset()
    assert not resolved.may_read_private


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

    assert registry.file_by_name("rollback_.nwb") is None
