"""Reading the broker's own tables.

Thin by design: routes ask questions in domain terms and get plain dataclasses
back, so `access.can_read` keeps operating on data rather than on queries, and
the permission logic stays testable without a database.

Tables are reached lazily. `schema.py` opens a connection when it is imported,
and a module that connects on import cannot be imported by a test that has no
database. Deferring the import to first use is the same shape `lab.py` uses for
the reflected Spyglass schema.

Reads do write: every permission decision lands in `AccessLog`, and quota is
derived from it. What a read never does is *create* a principal — a caller the
broker does not know stays unregistered rather than being invented, so an
unknown identity is limited to public data. Accounts come from logging in and
files from registering one.

Every function that touches the database is wrapped in `db.serialized`.
DataJoint shares one connection process-wide with no locking of its own, and
the routes run on a worker threadpool; see `db.py` for why that is the
conservative choice rather than a permanent one.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NamedTuple
from uuid import uuid4

import datajoint as dj

from spyglass_store.access import AccessRule, Principal
from spyglass_store.auth import Identity
from spyglass_store.db import db_now, serialized, window_start
from spyglass_store.lab import teams_for_github


@dataclass(frozen=True)
class FileRecord:
    """A registered file, as the routes need it.

    Attributes
    ----------
    file_id : str
        Opaque handle used in URLs.
    sha256 : str
        Content address; determines the object key.
    size_bytes : int
        Object size, charged against quota at URL-issue time.
    spyglass_name : str
        Name the client knows the file by.
    file_class : str
        Either raw or analysis.
    owner : str
        Account id that registered it.
    """

    file_id: str
    sha256: str
    size_bytes: int
    spyglass_name: str
    file_class: str
    owner: str


def _schema():
    """Return the broker's tables, declared on first use.

    A single accessor rather than one per table. Three separately cached
    lookups meant three caches to reset when the configuration changed, and a
    fixture that cleared some of them left the rest pointing at the old
    connection.
    """
    from spyglass_store import schema

    return schema.get_schema()


def tables():
    """Return `(Account, File, FileAccess)`, the three most used."""
    tbl = _schema()

    return tbl.Account, tbl.File, tbl.FileAccess


def _one(query) -> dict | None:
    """Return a single row as a dict, or None when nothing matched."""
    rows = query.fetch(as_dict=True)

    return rows[0] if rows else None


def _record(row: dict | None) -> FileRecord | None:
    """Build a `FileRecord` from a fetched row."""
    if row is None:
        return None

    return FileRecord(
        file_id=row["file_id"],
        sha256=row["sha256"],
        size_bytes=int(row["size_bytes"]),
        spyglass_name=row["spyglass_name"],
        file_class=row["file_class"],
        owner=str(row["owner"]),
    )


@serialized
def file_by_id(file_id: str) -> FileRecord | None:
    """Return the file with this id, or None.

    Parameters
    ----------
    file_id : str
        Opaque handle from a previous resolve.

    Returns
    -------
    FileRecord or None
    """
    _, File, _ = tables()

    return _record(_one(File & {"file_id": file_id}))


@serialized
def files_by_name(spyglass_name: str) -> tuple[FileRecord, ...]:
    """Return every registration of a Spyglass name, newest first.

    A name here is the primary key of a Spyglass file table, so within one
    Spyglass instance it identifies exactly one file. Several rows for a name
    are therefore not competing answers about *which* file — they are several
    people's declarations about the same one, differing in owner and
    visibility. The caller picks the declaration that applies to them.

    Newest first because the one case where content genuinely differs is a
    regenerated analysis file reusing its name, and the recent registration is
    the one a client asking by name means.

    Parameters
    ----------
    spyglass_name : str
        Name the client knows the file by.

    Returns
    -------
    tuple of FileRecord
    """
    _, File, _ = tables()
    rows = (File & {"spyglass_name": spyglass_name}).fetch(
        as_dict=True, order_by="registered DESC"
    )

    return tuple(_record(row) for row in rows)


@serialized
def files_by_sha256(sha256: str) -> tuple[FileRecord, ...]:
    """Return every registration of this content, newest first.

    Like `files_by_name`, and for the same reason: a hash is not a unique key
    here either. Deduplication is the designed-for case — two owners
    registering identical bytes each get a registration, sharing one object —
    so a hash lookup has as many rows as people who registered it.

    Returning one arbitrary row would be worse here than for a name. A hash
    identifies the *content* exactly, so every row is genuinely the file the
    caller asked for; picking one and finding it unreadable would refuse a
    caller who is party to a different registration of the very same bytes.

    Parameters
    ----------
    sha256 : str
        Lowercase hex digest.

    Returns
    -------
    tuple of FileRecord
    """
    _, File, _ = tables()
    rows = (File & {"sha256": sha256}).fetch(
        as_dict=True, order_by="registered DESC"
    )

    return tuple(_record(row) for row in rows)


@serialized
def rules_for_file(file_id: str) -> tuple[AccessRule, ...]:
    """Return every grant recorded against a file.

    An empty result is meaningful, not a lookup failure: a private file has no
    rows, and ownership is checked separately.

    Parameters
    ----------
    file_id : str
        File whose grants to read.

    Returns
    -------
    tuple of AccessRule
    """
    _, _, FileAccess = tables()
    rows = (FileAccess & {"file_id": file_id}).fetch(as_dict=True)

    return tuple(
        AccessRule(
            principal_type=Principal(row["principal_type"]),
            principal=row["principal"] or "",
        )
        for row in rows
    )


@serialized
def registration_for(
    sha256: str, spyglass_name: str, owner: str
) -> FileRecord | None:
    """Return this owner's existing registration of this content, or None.

    Registering is idempotent per owner and name: a client that retries after
    a dropped response must not accumulate rows. Two *different* owners
    registering the same bytes is not a duplicate — they each get a
    registration, and the object is what deduplicates.

    Parameters
    ----------
    sha256 : str
        Content hash being registered.
    spyglass_name : str
        Name the client knows the file by.
    owner : str
        Account id registering it.

    Returns
    -------
    FileRecord or None
    """
    _, File, _ = tables()
    query = File & {
        "sha256": sha256,
        "spyglass_name": spyglass_name,
        "owner": int(owner),
    }

    return _record(_one(query))


@serialized
def register_file(
    *,
    sha256: str,
    size_bytes: int,
    spyglass_name: str,
    file_class: str,
    owner: str,
    rules: Iterable[AccessRule] = (),
) -> FileRecord:
    """Record a file and the grants its declared visibility implies.

    The row and its grants go in one transaction. A file that existed with no
    rules would be readable by its owner alone, which is the safe direction to
    fail, but a *public* file whose grant was lost would be silently private
    and the owner would have no signal — so neither half is written alone.

    Parameters
    ----------
    sha256 : str
        Content hash. Determines the object key, so it is the deduplication
        key as well.
    size_bytes : int
        Declared size.
    spyglass_name : str
        Name the client knows the file by.
    file_class : str
        Either raw or analysis.
    owner : str
        Account id registering the file.
    rules : iterable of AccessRule, optional
        Grants to record. Empty for a private file.

    Returns
    -------
    FileRecord
        The newly registered file, with its generated `file_id`.
    """
    _, File, FileAccess = tables()
    file_id = uuid4().hex

    with dj.conn().transaction:
        File.insert1(
            {
                "file_id": file_id,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "spyglass_name": spyglass_name,
                "file_class": file_class,
                "owner": int(owner),
            }
        )
        FileAccess.insert(
            [
                {
                    "file_id": file_id,
                    "principal_type": rule.principal_type.value,
                    "principal": rule.principal,
                }
                for rule in rules
            ]
        )

    return FileRecord(
        file_id=file_id,
        sha256=sha256,
        size_bytes=size_bytes,
        spyglass_name=spyglass_name,
        file_class=file_class,
        owner=str(owner),
    )


def token_hash(token: str) -> str:
    """Return the stored form of a client token.

    Parameters
    ----------
    token : str
        The bearer token a client holds.

    Returns
    -------
    str
        Lowercase hex SHA-256 digest.
    """
    return hashlib.sha256(token.encode()).hexdigest()


@serialized
def upsert_account(user, lab_member: str | None) -> tuple[str, str]:
    """Find or create the broker account for a GitHub identity.

    Keyed on `github_id`, not login: GitHub logins can be renamed, and a
    rename must not orphan a user's files or silently mint them a second
    account.

    A login that matches a `LabMember` is verified on sight — the lab already
    vouched for that person by recording their GitHub name. Everyone else
    starts unverified and reaches public data only.

    **That makes `LabMember.LabMemberInfo` a trust root, and it must be
    admin-only writable on any instance this broker serves.** Whoever can add
    a `github_user_name` row decides who may upload. On the deployments this
    is built for, that table is read-only to everyone but an admin, which is
    what makes promotion-on-sight safe rather than self-service — the same
    condition `LabTeam` already has to meet for team grants to mean anything.

    A deployment that cannot guarantee it should not use this path: drop the
    promotion here and require an explicit admin action instead. See
    `deploy/README.md`.

    Parameters
    ----------
    user : GitHubUser
        Identity returned by the device flow.
    lab_member : str or None
        Matching `lab_member_name`, or None for an unaffiliated reader.

    Returns
    -------
    tuple of str
        `(account_id, tier)`.
    """
    Account, _, _ = tables()
    existing = _one(Account & {"github_id": user.github_id})

    if existing is not None:
        # Refresh the cached login so a rename does not leave stale audit
        # output; tier and affiliation are deliberately not re-derived here.
        if existing["github_login"] != user.github_login:
            Account.update1(
                {
                    "account_id": existing["account_id"],
                    "github_login": user.github_login,
                }
            )
        return str(existing["account_id"]), existing["tier"]

    tier = "verified" if lab_member else "unverified"
    Account.insert1(
        {
            "github_id": user.github_id,
            "github_login": user.github_login,
            "lab_member_name": lab_member,
            "tier": tier,
            "github_created": user.created,
        }
    )
    row = _one(Account & {"github_id": user.github_id})

    return str(row["account_id"]), tier


@serialized
def issue_token(account_id: str, ttl_days: int | None = None) -> str:
    """Mint a broker token for an account and store only its hash.

    A token is a bearer credential: whoever holds it is the account. Giving it
    a lifetime bounds the damage from one that leaks, and costs nothing while
    logging in again is a single command. Expiry is set here rather than left
    to a cleanup job so a token is never valid longer than intended, even if
    nothing ever sweeps the table.

    Parameters
    ----------
    account_id : str
        Account the token authenticates.
    ttl_days : int, optional
        Lifetime. Defaults to the configured value; None or zero there means
        the token does not expire.

    Returns
    -------
    str
        The token. This is the only time it exists in readable form; it is
        not recoverable from the database afterwards.
    """
    from spyglass_store.settings import get_settings

    ClientToken = _client_token()
    token = secrets.token_urlsafe(32)

    if ttl_days is None:
        ttl_days = get_settings().token_ttl_days

    expires = db_now() + timedelta(days=ttl_days) if ttl_days else None

    ClientToken.insert1(
        {
            "token_hash": token_hash(token),
            "account_id": int(account_id),
            "expires": expires,
        }
    )

    return token


@dataclass(frozen=True)
class AccountRecord:
    """A broker account, as administration needs it."""

    account_id: str
    github_id: int
    github_login: str
    lab_member_name: str | None
    tier: str
    suspended: bool


def _account(row: dict | None) -> AccountRecord | None:
    """Build an `AccountRecord` from a fetched row."""
    if row is None:
        return None

    return AccountRecord(
        account_id=str(row["account_id"]),
        github_id=int(row["github_id"]),
        github_login=row["github_login"],
        lab_member_name=row["lab_member_name"],
        tier=row["tier"],
        suspended=bool(row["suspended"]),
    )


@serialized
def accounts() -> tuple[AccountRecord, ...]:
    """Return every account, oldest first."""
    Account, _, _ = tables()
    rows = Account.fetch(as_dict=True, order_by="account_id")

    return tuple(_account(row) for row in rows)


@serialized
def account_by_login(github_login: str) -> AccountRecord | None:
    """Return the account for a GitHub login, or None."""
    Account, _, _ = tables()

    return _account(_one(Account & {"github_login": github_login}))


@serialized
def set_tier(account_id: str, tier: str) -> None:
    """Change what an account is trusted to do.

    Parameters
    ----------
    account_id : str
        Account to change.
    tier : str
        One of the names in `access.Tier`.
    """
    Account, _, _ = tables()
    Account.update1({"account_id": int(account_id), "tier": tier})


@serialized
def set_suspended(account_id: str, suspended: bool) -> None:
    """Suspend or reinstate an account.

    Suspension is checked when a token is resolved and again at login, so it
    takes effect on the next request rather than whenever a token happens to
    expire. Tokens are left in place: reinstating should not also require the
    user to log in again.
    """
    Account, _, _ = tables()
    Account.update1(
        {"account_id": int(account_id), "suspended": int(suspended)}
    )


@serialized
def files_for_owner(account_id: str) -> tuple[FileRecord, ...]:
    """Return every file an account registered, newest first."""
    _, File, _ = tables()
    rows = (File & {"owner": int(account_id)}).fetch(
        as_dict=True, order_by="registered DESC"
    )

    return tuple(_record(row) for row in rows)


@serialized
def all_files() -> tuple[FileRecord, ...]:
    """Return every registered file. Used by reconciliation."""
    _, File, _ = tables()

    return tuple(_record(row) for row in File.fetch(as_dict=True))


@serialized
def recent_access(
    account_id: str | None = None, hours: int = 24
) -> tuple[dict, ...]:
    """Return audit entries in a window, newest first.

    Parameters
    ----------
    account_id : str, optional
        Restrict to one account. All accounts when omitted.
    hours : int, optional
        Window length.

    Returns
    -------
    tuple of dict
    """
    AccessLog = _access_log()
    since = window_start(hours)
    query = AccessLog & f"timestamp >= '{since:%Y-%m-%d %H:%M:%S}'"

    if account_id:
        query = query & {"account_id": int(account_id)}

    return tuple(query.fetch(as_dict=True, order_by="timestamp DESC"))


@serialized
def revoke_tokens(account_id: str) -> int:
    """Invalidate every token an account holds.

    The remedy when a credential leaks. Deleting the rows rather than marking
    them spent keeps `identity_for_token` a single lookup with nothing to
    interpret.

    Parameters
    ----------
    account_id : str
        Account whose tokens to drop.

    Returns
    -------
    int
        How many were revoked.
    """
    ClientToken = _client_token()
    query = ClientToken & {"account_id": int(account_id)}
    count = len(query)
    query.delete_quick()

    return count


def identity_for_token(token: str) -> Identity | None:
    """Resolve a broker token to the identity holding it.

    Parameters
    ----------
    token : str
        Bearer token presented by a client.

    Returns
    -------
    Identity or None
        None when the token is unknown or expired. Unknown and expired are
        deliberately indistinguishable to the caller.
    """
    Account, _, _ = tables()
    ClientToken = _client_token()

    row = _one((ClientToken & {"token_hash": token_hash(token)}) * Account)

    if row is None:
        return None

    if row.get("suspended"):
        # Checked here rather than by deleting tokens, so reinstating does not
        # also force the user through a fresh login.
        return None

    expires = row.get("expires")
    if expires is not None and expires < db_now():
        return None

    login = row["github_login"]

    return Identity(
        github_id=row["github_id"],
        github_login=login,
        account_id=str(row["account_id"]),
        tier=row["tier"],
        teams=frozenset(teams_for_github(login)),
    )


def _client_token():
    """Return the `ClientToken` table."""
    return _schema().ClientToken


class Usage(NamedTuple):
    """What an account has been charged in a window.

    Attributes
    ----------
    total_bytes : int
        Sum over *distinct* files, not over requests. See `usage_since`.
    earliest : datetime or None
        Timestamp of the oldest counted read, or None if there were none.
    files : frozenset of str
        File ids already charged, so re-reading one is not charged twice.
    """

    total_bytes: int
    earliest: datetime | None
    files: frozenset[str]


#: One row per distinct file charged in the window, carrying the window's
#: totals. Both aggregations happen in SQL, and they have to happen in one
#: statement because the caller needs the totals *and* the file ids: the inner
#: `GROUP BY` collapses a file's many read events into the single charge quota
#: counts, and the window functions total those charges across files.
#:
#: `MAX(size_bytes)` rather than any particular row: the sizes recorded for one
#: file are the store's answer for the same object and so agree, and where a
#: declared size once stood in they do not — taking the largest errs toward
#: charging more, which is the safe direction for a guardrail.
#:
#: A charge with no `file_id` is excluded. It could never match the caller's
#: already-charged check, so it would be billed again on every request. Nothing
#: writes such a row today; excluding it here keeps that true.
_USAGE_SQL = """
SELECT charged.file_id,
       SUM(charged.size_bytes) OVER () AS total_bytes,
       MIN(charged.first_read)  OVER () AS earliest
FROM (
    SELECT file_id,
           MAX(size_bytes) AS size_bytes,
           MIN(timestamp)  AS first_read
    FROM {table}
    WHERE account_id = %s
      AND action     = %s
      AND granted    = 1
      AND file_id IS NOT NULL
      AND timestamp >= %s
    GROUP BY file_id
) AS charged
"""


@serialized
def usage_since(
    account_id: str, window_hours: int, action: str = "read"
) -> Usage:
    """Return what an account has been charged in a rolling window.

    **Counted per distinct file, not per request.** A stable content URL
    re-signs on every call, so streaming one file with range requests produces
    hundreds of read events for a single transfer. Charging each of them would
    bill a ten gigabyte session as terabytes and throttle exactly the
    large-file streaming this service exists to enable.

    Counting distinct files instead answers the question quota is really
    asking: how much data was this account permitted to pull. Re-reading a
    file inside the window is free, which is the right answer anyway — the
    reader could have kept the first copy.

    Only granted rows for the named action count. A refusal transfers nothing,
    a resolve hands out a name rather than bytes, and an upload is charged
    against a different allowance than a download.

    **MySQL does the folding.** The log grows with requests, not with files, so
    reading it row by row to sum in Python made a cheap check scale with how
    hard the account had been hammering the service. What comes back now is one
    row per distinct file, which is quota's own unit; see `_USAGE_SQL`.

    The window is measured against the database's clock rather than the
    broker host's. `datetime.now()` is naive and local; MySQL stores these
    timestamps as UTC and returns them in the session time zone, so mixing the
    two slides the window by the offset between them.

    Parameters
    ----------
    account_id : str
        Account to total.
    window_hours : int
        Length of the rolling window.
    action : str, optional
        Which volume to total: "read" for downloads, "register" for uploads.

    Returns
    -------
    Usage
    """
    AccessLog = _access_log()

    rows = (
        dj.conn()
        .query(
            _USAGE_SQL.format(table=AccessLog.full_table_name),
            (int(account_id), action, window_start(window_hours)),
            as_dict=True,
        )
        .fetchall()
    )

    if not rows:
        return Usage(0, None, frozenset())

    return Usage(
        total_bytes=int(rows[0]["total_bytes"]),
        earliest=rows[0]["earliest"],
        files=frozenset(row["file_id"] for row in rows),
    )


@serialized
def log_access(
    *,
    identity: Identity,
    action: str,
    granted: bool,
    file_id: str | None = None,
    size_bytes: int = 0,
    source_ip: str = "",
) -> None:
    """Record one permission decision.

    Failures are swallowed. An audit write that 500s a legitimate read turns a
    logging outage into a service outage, and the broker's job is to decide,
    not to narrate. The cost is that the log is a floor rather than a ledger:
    quota reconciliation must treat a missing row as under-counting, never as
    evidence that no access occurred.

    Parameters
    ----------
    identity : Identity
        The caller. An empty `account_id` is recorded as a null account with
        `github_id` kept, since that pairing is what an audit looks for.
    action : str
        One of resolve, read, register, visibility, login.
    granted : bool
        Whether the request was allowed.
    file_id : str, optional
        File the decision concerned, when there is one.
    size_bytes : int, optional
        Charged at URL-issue time. The broker leaves the data path, so this
        is what the reader *may* transfer, not what they did.
    source_ip : str, optional
        Caller address, for audit.
    """
    AccessLog = _access_log()

    try:
        AccessLog.insert1(
            {
                "account_id": int(identity.account_id)
                if identity.account_id
                else None,
                "github_id": identity.github_id or None,
                "action": action,
                "file_id": file_id,
                "granted": bool(granted),
                "size_bytes": size_bytes,
                "source_ip": source_ip[:45],
            }
        )
    except Exception as err:  # never fail a request over an audit row
        logging.getLogger(__name__).warning("access log write failed: %s", err)


def _access_log():
    """Return the `AccessLog` table."""
    return _schema().AccessLog


@serialized
def replace_rules(file_id: str, rules: Iterable[AccessRule]) -> None:
    """Swap a file's grants for a new set, atomically.

    Visibility changes take effect with no re-upload, so this rewrites only
    the grant rows and never touches the object. Narrowing access is the case
    that has to be exact: a moment where both the old and new grants are
    absent is harmless, but one where both are present would leave a file
    briefly readable by an audience the owner has just revoked.

    Parameters
    ----------
    file_id : str
        File whose visibility is changing.
    rules : iterable of AccessRule
        Grants the new visibility implies. Empty makes the file private.
    """
    _, _, FileAccess = tables()
    new = [
        {
            "file_id": file_id,
            "principal_type": rule.principal_type.value,
            "principal": rule.principal,
        }
        for rule in rules
    ]

    with dj.conn().transaction:
        (FileAccess & {"file_id": file_id}).delete_quick()
        FileAccess.insert(new)
