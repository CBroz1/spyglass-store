"""Tests for the admin CLI.

The phase this completes says routine operations must need no direct SQL, so
these check that each command reaches a real database and prints something an
operator can act on — not that the wording is stable.
"""

from __future__ import annotations

import pytest

from spyglass_store.cli import main


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


@pytest.fixture
def uploader(broker_tables, member):
    """A verified account for that member."""
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


@pytest.fixture
def admin(db, broker_tables, member, uploader):
    """An account with a file, reachable by login."""
    from spyglass_store import registry
    from spyglass_store.access import Scope, rules_for

    file = registry.register_file(
        sha256="a" * 64,
        size_bytes=2048,
        spyglass_name="cli_.nwb",
        file_class="raw",
        owner=uploader,
        rules=rules_for(Scope.GROUP, ["teamA"]),
    )

    return member, file


def test_account_list_shows_the_account(admin, capsys):
    assert main(["account", "list"]) == 0
    assert "ada" in capsys.readouterr().out


def test_account_show_reports_tier_teams_and_usage(admin, capsys):
    login, _ = admin

    assert main(["account", "show", login]) == 0
    out = capsys.readouterr().out

    assert "verified" in out
    assert "teamA" in out
    assert "downloaded" in out


def test_an_unknown_login_exits_with_a_message(db, broker_tables):
    with pytest.raises(SystemExit) as exited:
        main(["account", "show", "nobody"])

    assert "nobody" in str(exited.value)


def test_set_tier_changes_what_an_account_may_do(admin, capsys):
    from spyglass_store import registry

    login, _ = admin
    assert main(["account", "set-tier", login, "trusted"]) == 0

    assert registry.account_by_login(login).tier == "trusted"


def test_suspending_stops_every_live_token(admin, capsys):
    """The command has to actually bite, or it is theatre."""
    from spyglass_store import registry

    login, _ = admin
    account = registry.account_by_login(login)
    token = registry.issue_token(account.account_id)

    assert registry.identity_for_token(token) is not None

    main(["account", "suspend", login])

    assert registry.identity_for_token(token) is None

    # Reinstating does not force the user through a fresh login.
    main(["account", "suspend", login, "--undo"])

    assert registry.identity_for_token(token) is not None


def test_revoking_tokens_leaves_the_account_usable(admin):
    """Revocation is not suspension: they can log in again."""
    from spyglass_store import registry

    login, _ = admin
    account = registry.account_by_login(login)
    token = registry.issue_token(account.account_id)

    main(["account", "revoke-tokens", login])

    assert registry.identity_for_token(token) is None
    assert not registry.account_by_login(login).suspended


def test_file_list_and_show(admin, object_store, capsys):
    login, file = admin

    assert main(["file", "list", "--owner", login]) == 0
    assert "cli_.nwb" in capsys.readouterr().out

    assert main(["file", "show", file.file_id], store=object_store) == 0
    out = capsys.readouterr().out

    assert "teamA" in out
    assert "bytes not in the store" in out  # nothing was uploaded


def test_audit_lists_decisions(admin, capsys):
    from spyglass_store import registry
    from spyglass_store.auth import Identity

    login, file = admin
    account = registry.account_by_login(login)
    registry.log_access(
        identity=Identity(github_id=9001, account_id=account.account_id),
        action="read",
        granted=True,
        file_id=file.file_id,
        size_bytes=2048,
        source_ip="203.0.113.7",
    )

    assert main(["audit", "--login", login]) == 0
    out = capsys.readouterr().out

    assert "read" in out
    assert "203.0.113.7" in out


def test_top_ranks_by_volume(admin, capsys):
    from spyglass_store import registry
    from spyglass_store.auth import Identity

    login, file = admin
    account = registry.account_by_login(login)
    registry.log_access(
        identity=Identity(github_id=9001, account_id=account.account_id),
        action="read",
        granted=True,
        file_id=file.file_id,
        size_bytes=5 * 1024**3,
        source_ip="",
    )

    assert main(["top"]) == 0
    out = capsys.readouterr().out

    assert login in out
    assert "5.00" in out


def test_reconcile_reports_a_registration_with_no_bytes(
    admin, object_store, capsys
):
    """A non-zero exit lets a scheduled check gate on the result."""
    assert main(["reconcile"], store=object_store) == 1
    out = capsys.readouterr().out

    assert "no bytes in the store" in out
    assert "cli_.nwb" in out


def test_reconcile_never_deletes(admin, object_store, capsys):
    """Diagnosis, not cleanup. Acting on it is a separate decision."""
    import httpx

    from spyglass_store.storage import object_key

    upload = object_store.presigned_put(object_key("b" * 64), 300)
    httpx.put(upload.url, content=b"orphan", headers=upload.headers)

    main(["reconcile"], store=object_store)
    out = capsys.readouterr().out

    assert "no registration" in out
    assert object_store.exists(object_key("b" * 64)), "must not delete"
