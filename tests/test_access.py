"""Tests for the read-permission decision.

The decision is a pure function, so these cover the matrix exhaustively. Every
false case matters more than the true ones: a wrong deny is an annoyance, a
wrong grant is a data leak.
"""

import pytest

from spyglass_store.access import (
    AccessRule,
    Principal,
    Reader,
    Scope,
    can_read,
    is_public,
    rules_for,
)

OWNER = "acct-1"
OTHER = "acct-2"


def team_rule(name: str) -> AccessRule:
    return AccessRule(Principal.TEAM, name)


# --------------------------------------------------------------------------- #
# Declaring visibility
# --------------------------------------------------------------------------- #
def test_public_yields_one_public_rule() -> None:
    assert rules_for(Scope.PUBLIC) == (AccessRule(Principal.PUBLIC),)


def test_private_yields_no_rules() -> None:
    """Ownership is checked separately, so private needs no row."""
    assert rules_for(Scope.PRIVATE) == ()


def test_group_yields_one_rule_per_team() -> None:
    """A file can be shared with several teams; an enum could not say this."""
    assert rules_for(Scope.GROUP, ["analysis", "seizure"]) == (
        team_rule("analysis"),
        team_rule("seizure"),
    )


def test_group_deduplicates_teams() -> None:
    assert rules_for(Scope.GROUP, ["a", "a", "b"]) == (
        team_rule("a"),
        team_rule("b"),
    )


def test_group_without_teams_is_an_error() -> None:
    """Silently producing an owner-only file would surprise the owner."""
    with pytest.raises(ValueError, match="requires at least one team"):
        rules_for(Scope.GROUP, [])


def test_declared_scope_ignores_teams_when_public() -> None:
    """Teams are meaningless once a file is public; they must not linger."""
    assert rules_for(Scope.PUBLIC, ["analysis"]) == (
        AccessRule(Principal.PUBLIC),
    )


# --------------------------------------------------------------------------- #
# Deciding access
# --------------------------------------------------------------------------- #
def test_no_rules_denies_a_stranger() -> None:
    """Deny by default: an empty rule set grants nothing."""
    assert can_read((), Reader(OTHER), OWNER) is False


def test_owner_reads_their_own_private_file() -> None:
    assert can_read((), Reader(OWNER), OWNER) is True


def test_public_grants_anyone() -> None:
    rules = rules_for(Scope.PUBLIC)
    assert can_read(rules, Reader(OTHER), OWNER) is True


def test_team_member_is_granted() -> None:
    rules = rules_for(Scope.GROUP, ["seizure"])
    reader = Reader(OTHER, frozenset({"seizure"}))
    assert can_read(rules, reader, OWNER) is True


def test_non_member_is_denied() -> None:
    rules = rules_for(Scope.GROUP, ["seizure"])
    reader = Reader(OTHER, frozenset({"analysis"}))
    assert can_read(rules, reader, OWNER) is False


def test_any_one_matching_team_suffices() -> None:
    rules = rules_for(Scope.GROUP, ["a", "b"])
    reader = Reader(OTHER, frozenset({"b", "c"}))
    assert can_read(rules, reader, OWNER) is True


def test_direct_account_grant_is_honored() -> None:
    rules = (AccessRule(Principal.ACCOUNT, OTHER),)
    assert can_read(rules, Reader(OTHER), OWNER) is True


def test_account_grant_does_not_leak_to_other_accounts() -> None:
    rules = (AccessRule(Principal.ACCOUNT, OTHER),)
    assert can_read(rules, Reader("acct-3"), OWNER) is False


def test_sharing_a_team_with_the_owner_grants_nothing() -> None:
    """No ambient access.

    Spyglass's delete guard is permissive among collaborators on purpose.
    Publication is the opposite case: being on some team the owner is also on
    must not imply access to a file that was never shared with that team.
    """
    rules = rules_for(Scope.GROUP, ["seizure"])
    colleague = Reader(OTHER, frozenset({"analysis", "lab-wide"}))
    assert can_read(rules, colleague, OWNER) is False


def test_anonymous_reader_never_matches_the_owner() -> None:
    """An empty account id must not compare equal to an empty owner id."""
    assert can_read((), Reader(""), "") is False


def test_revoking_team_membership_takes_effect_without_reupload() -> None:
    """Access follows current membership, not a snapshot taken at upload."""
    rules = rules_for(Scope.GROUP, ["seizure"])
    before = Reader(OTHER, frozenset({"seizure"}))
    after = Reader(OTHER, frozenset())

    assert can_read(rules, before, OWNER) is True
    assert can_read(rules, after, OWNER) is False


# --------------------------------------------------------------------------- #
# Public check, used before a reader is resolved
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("scope", "teams", "expected"),
    [
        (Scope.PUBLIC, (), True),
        (Scope.PRIVATE, (), False),
        (Scope.GROUP, ("a",), False),
    ],
)
def test_is_public_matches_declared_scope(scope, teams, expected) -> None:
    assert is_public(rules_for(scope, teams)) is expected
