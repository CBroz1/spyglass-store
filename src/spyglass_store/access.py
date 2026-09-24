"""What an identity may do. The whole rule lives here.

Two questions, and both are answered in this module so that a developer
reading one file sees the entire policy:

- **May they read this file?** `may_read` — the grants on the file, and
  whether their tier reaches beyond public data.
- **May they upload at all?** `may_upload` — tier alone.

A third question, *how much* may they move, is deliberately elsewhere: volume
limits are a guardrail against runaway usage, not a permission, and merging
them here would mean promoting someone to give them headroom.

`can_read` below is the grant half on its own, kept separate because it is a
pure statement about rows and is exhaustively tested as such. `may_read` is
the decision the service actually makes.

The grant rule is deliberately small: a file is readable if it is public, or
the reader owns it, or the reader belongs to a team it was shared with.

Two properties are worth defending as the broker grows:

- **Deny by default.** An empty rule set grants nothing. Every path that says
  yes has to say so explicitly.

  Not to be confused with the *registration* default, which is public: a caller
  who omits `visibility` is asking for a public file, and `rules_for` writes an
  explicit public grant to say so. The distinction matters because it is what
  keeps the failure direction safe — a grant row lost to a failed transaction
  leaves a file readable by its owner alone, never by everyone, whatever the
  uploader asked for.
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


class Tier(str, Enum):
    """What an account is trusted to do, independent of any one file.

    The names are also the values stored in `schema.Account.tier`; a test
    pins the two vocabularies together, since DataJoint spells its enum as a
    string and cannot import this one.
    """

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    ADMIN = "admin"

    @property
    def may_read_private(self) -> bool:
        """True if this tier reaches anything beyond public files.

        An unverified account is a GitHub identity the lab has not vouched
        for. Accounts are free and instant, so admitting one to public data
        costs little and admitting it to shared data would cost the lab its
        access control.
        """
        return self is not Tier.UNVERIFIED

    @property
    def may_upload(self) -> bool:
        """True if this tier may write to shared storage.

        Uploading consumes storage the lab pays for and publishes bytes under
        the lab's name, so it asks more than reading does.
        """
        return self is not Tier.UNVERIFIED

    @classmethod
    def parse(cls, value) -> Tier:
        """Return the tier named by `value`, defaulting to the tightest.

        An unrecognised name is the tightest tier rather than an error: a typo
        in a database row should cost someone their upload rights, not the
        broker its ability to answer.
        """
        try:
            return cls(str(value))
        except ValueError:
            return cls.UNVERIFIED


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
        Broker account id. Empty for an authenticated caller the broker has
        no account for.
    teams : frozenset[str]
        Team names the reader belongs to, from Spyglass's `LabTeam`.
    tier : Tier
        What this account is trusted to do. Defaults to the tightest, so a
        caller assembled without one is never accidentally privileged.
    """

    account_id: str
    teams: frozenset[str] = frozenset()
    tier: Tier = Tier.UNVERIFIED


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


def may_read(
    rules: Iterable[AccessRule], reader: Reader, owner_id: str
) -> bool:
    """Return True if `reader` may read a file owned by `owner_id`.

    The decision the service makes: the grants allow it *and* the reader's
    tier reaches that far. An unverified account is held to public files
    however generously a file was shared, because the lab has not vouched for
    whoever holds it.

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
    """
    rules = tuple(rules)

    return can_read(rules, reader, owner_id) and (
        reader.tier.may_read_private or is_public(rules)
    )


def may_upload(reader: Reader) -> bool:
    """Return True if `reader` may register and upload files.

    Requires an account as well as a tier: an authenticated caller the broker
    has never seen has no owner to record a file against.

    Parameters
    ----------
    reader : Reader
        The identity asking.

    Returns
    -------
    bool
    """
    return bool(reader.account_id) and reader.tier.may_upload
