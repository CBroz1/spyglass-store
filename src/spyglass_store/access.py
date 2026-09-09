"""Who may read a file.

The rule is deliberately small: a file is readable if it is public, or the
reader owns it, or the reader belongs to a team it was shared with.

Two properties are worth defending as the broker grows:

- **Deny by default.** An empty rule set grants nothing. Every path that says
  yes has to say so explicitly.
- **No ambient access.** Membership is not inferred from sharing a team with
  the owner. Spyglass uses that permissive rule to guard against accidental
  deletes among known collaborators; outbound publication is the opposite
  case, where access should be explicit and should not drift as team
  membership changes elsewhere.

The decision is a pure function over data so it can be exhaustively tested
without a database, an object store, or a network.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class Scope(str, Enum):
    """Visibility a file owner declares."""

    PRIVATE = "private"
    GROUP = "group"
    PUBLIC = "public"


class Principal(str, Enum):
    """Kind of entity a rule grants to."""

    ACCOUNT = "account"
    TEAM = "team"
    PUBLIC = "public"


@dataclass(frozen=True)
class AccessRule:
    """One grant on one file.

    Attributes
    ----------
    principal_type : Principal
        Whether this grants to an account, a team, or everyone.
    principal : str
        Account id or team name. Empty for a public grant.
    """

    principal_type: Principal
    principal: str = ""


@dataclass(frozen=True)
class Reader:
    """The identity asking to read.

    Attributes
    ----------
    account_id : str
        Broker account id.
    teams : frozenset[str]
        Team names the reader belongs to, from Spyglass's `LabTeam`.
    """

    account_id: str
    teams: frozenset[str] = frozenset()


def rules_for(
    scope: Scope, teams: Iterable[str] = ()
) -> tuple[AccessRule, ...]:
    """Translate a declared visibility into the rules it implies.

    Parameters
    ----------
    scope : Scope
        Visibility the owner chose.
    teams : iterable of str, optional
        Team names, used only when `scope` is `GROUP`.

    Returns
    -------
    tuple of AccessRule
        Rules to store for the file. Empty for `PRIVATE`, since ownership is
        checked separately and needs no row.

    Raises
    ------
    ValueError
        If `GROUP` is given without teams, which would silently produce a
        file nobody but the owner can read.
    """
    if scope is Scope.PUBLIC:
        return (AccessRule(Principal.PUBLIC),)

    if scope is Scope.PRIVATE:
        return ()

    named = tuple(dict.fromkeys(teams))  # dedupe, keep order
    if not named:
        raise ValueError(
            "visibility 'group' requires at least one team; use 'private' to "
            "restrict a file to its owner"
        )

    return tuple(AccessRule(Principal.TEAM, team) for team in named)


def can_read(
    rules: Iterable[AccessRule], reader: Reader, owner_id: str
) -> bool:
    """Return True if `reader` may read a file owned by `owner_id`.

    Parameters
    ----------
    rules : iterable of AccessRule
        Grants recorded for the file.
    reader : Reader
        The identity asking.
    owner_id : str
        Account id that registered the file.

    Returns
    -------
    bool
        True if access is granted.
    """
    if reader.account_id and reader.account_id == owner_id:
        return True

    for rule in rules:
        if rule.principal_type is Principal.PUBLIC:
            return True
        if (
            rule.principal_type is Principal.ACCOUNT
            and rule.principal == reader.account_id
        ):
            return True
        if (
            rule.principal_type is Principal.TEAM
            and rule.principal in reader.teams
        ):
            return True

    return False


def is_public(rules: Iterable[AccessRule]) -> bool:
    """Return True if a file is readable without an account.

    Unverified accounts are limited to public files, so this is checked before
    a reader is resolved.
    """
    return any(r.principal_type is Principal.PUBLIC for r in rules)
