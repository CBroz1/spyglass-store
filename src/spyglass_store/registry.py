"""Reading the broker's own tables.

Thin by design: routes ask questions in domain terms and get plain dataclasses
back, so `access.can_read` keeps operating on data rather than on queries, and
the permission logic stays testable without a database.

Tables are reached lazily. `schema.py` opens a connection when it is imported,
and a module that connects on import cannot be imported by a test that has no
database. Deferring the import to first use is the same shape `lab.py` uses for
the reflected Spyglass schema.

Nothing here writes. Resolving a caller who has no account yields an
unregistered identity rather than creating one, so the read path needs no
insert privilege and an unknown caller is limited to public files.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from spyglass_store.access import AccessRule, Principal
from spyglass_store.auth import Identity
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


@lru_cache(maxsize=1)
def tables():
    """Return the broker tables, importing the schema on first use.

    Returns
    -------
    tuple
        `(Account, File, FileAccess)` table classes.
    """
    from spyglass_store import schema

    return schema.Account, schema.File, schema.FileAccess


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


def file_by_name(spyglass_name: str) -> FileRecord | None:
    """Return the file registered under this Spyglass name, or None.

    Parameters
    ----------
    spyglass_name : str
        Name the client knows the file by.

    Returns
    -------
    FileRecord or None
    """
    _, File, _ = tables()

    return _record(_one(File & {"spyglass_name": spyglass_name}))


def file_by_sha256(sha256: str) -> FileRecord | None:
    """Return the file with this content hash, or None.

    Parameters
    ----------
    sha256 : str
        Lowercase hex digest.

    Returns
    -------
    FileRecord or None
    """
    _, File, _ = tables()

    return _record(_one(File & {"sha256": sha256}))


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


def resolve_account(identity: Identity) -> Identity:
    """Fill in the broker account and lab teams for a verified identity.

    A caller GitHub recognizes but the broker does not is *authenticated
    without being registered*: they keep an empty `account_id`, stay at the
    unverified tier, and so reach only public files. That is deliberate — the
    read path creates nothing, so it needs no write privilege.

    Parameters
    ----------
    identity : Identity
        Result of verifying the bearer token, carrying `github_id`.

    Returns
    -------
    Identity
        The same identity with `account_id`, `tier`, and `teams` populated
        where the broker knows them.
    """
    Account, _, _ = tables()
    row = _one(Account & {"github_id": identity.github_id})

    if row is None:
        return identity

    login = row.get("github_login") or identity.github_login

    return Identity(
        github_id=identity.github_id,
        github_login=login,
        account_id=str(row["account_id"]),
        tier=row["tier"],
        teams=frozenset(teams_for_github(login)),
    )
