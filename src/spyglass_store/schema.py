"""Broker tables, in a DataJoint schema separate from any Spyglass schema.

The broker shares the ServerHost MySQL instance with Spyglass but owns its own
schema. It connects through `dj.config`, the same mechanism Spyglass uses, so
no separate connection configuration is needed.

Two consequences worth stating plainly:

- Access control lives here, not in Spyglass. `Account` carries a *nullable*
  reference to a lab member, so a reader with no lab affiliation is a valid
  account without putting access-control rows in a scientific metadata table.
- Availability is shared. A client already needs this MySQL instance to
  discover which files exist, so the broker is a permission and metering
  service rather than an independent identity provider.

Teams are read from Spyglass's `LabTeam` rather than duplicated, so admins
curate membership in one place. That requires `LabTeam` be admin-only writable
on this instance; otherwise a user could add themselves to a team and grant
themselves access.
"""

from __future__ import annotations

from functools import lru_cache
from types import SimpleNamespace

import datajoint as dj

from spyglass_store.settings import get_settings


@lru_cache(maxsize=1)
def get_schema() -> SimpleNamespace:
    """Declare the broker's tables, connecting on first use.

    Deliberately not at import time. `dj.schema` connects and declares as soon
    as it is evaluated, so a module that did this at the top level could not be
    imported without a live database already configured with the right prefix —
    which made every consumer work around it: lazy accessors in `registry`, and
    a fixture in the test suite whose whole job was controlling when the import
    happened.

    Deferring it means the connection is made when the tables are first used,
    which is the moment a database is genuinely required.

    Returns
    -------
    types.SimpleNamespace
        The table classes, reachable by name.
    """
    schema = dj.schema(f"{get_settings().schema_prefix}_broker")

    @schema
    class Account(dj.Manual):
        """A GitHub identity known to the broker.

        Keyed on an internal id with `github_id` unique, so adding ORCID or
        institutional SSO later is a feature rather than a migration.
        """

        definition = """
        account_id           : int auto_increment
        ---
        github_id            : bigint        # immutable; logins are renameable
        github_login         : varchar(64)   # cached for display only
        lab_member_name=null : varchar(80)   # null for unaffiliated readers
        tier='unverified'    : enum('unverified','verified','trusted','admin')
        github_created       : date          # for the minimum-age check
        suspended=0          : bool          # refuses login and every live token
        created=CURRENT_TIMESTAMP : timestamp
        unique index (github_id)
        """

    @schema
    class ClientToken(dj.Manual):
        """A broker-issued bearer token, stored as a hash.

        The token itself is never written down. A leaked database yields hashes,
        and a hash cannot be presented as a credential. SHA-256 with no salt or
        stretching is right here and would be wrong for a password: these are 256
        bits of `secrets.token_urlsafe` output, so there is no guessable input to
        slow an attacker down over.

        Issuing one is also what lets the GitHub token be discarded. The client
        holds something that is meaningless to GitHub and revocable here, which is
        the whole reason for registering an OAuth app rather than passing a
        `gh` credential around.
        """

        definition = """
        token_hash   : char(64)     # sha256 of the token the client holds
        ---
        -> Account
        issued=CURRENT_TIMESTAMP : timestamp
        expires=null : timestamp    # null: no expiry
        """

    @schema
    class File(dj.Manual):
        """A registered object, addressed by content hash.

        `parent` records the raw file an analysis file was derived from, read
        from Spyglass's `AnalysisNwbfile` when the file is registered. It is a
        `spyglass_name` rather than a `file_id` because a name may carry
        several registrations — different owners declaring the same file — and
        the useful question is which of *those* a reader is party to, not which
        one row was picked at registration.

        Recorded once and not re-derived: `AnalysisNwbfile` is user-writable,
        so a live lookup would let someone re-point the provenance of an
        existing registration. See `nwbfile.py`.

        `inherits` says whether this file's audience is its own or its raw's.
        A registration that declared no visibility takes the raw's and follows
        it, so re-scoping a session re-scopes its results. One that declared a
        visibility keeps it — wider or narrower than the raw, either way —
        because that was a choice, and `PATCH /visibility` clears the flag for
        the same reason.
        """

        definition = """
        file_id       : char(32)      # opaque handle used in URLs
        ---
        sha256        : char(64)      # content address; determines the object key
        size_bytes    : bigint
        spyglass_name : varchar(255)  # name the client knows it by
        file_class    : enum('raw','analysis')
        parent=null   : varchar(64)   # raw this was derived from; see nwbfile.py
        inherits=0    : bool          # take the parent's audience, and follow it
        -> Account.proj(owner='account_id')
        registered=CURRENT_TIMESTAMP : timestamp
        index (sha256)
        index (spyglass_name)
        index (parent)
        """

    @schema
    class FileAccess(dj.Manual):
        """Who may read a file.

        A file is readable if it is public, or the reader belongs to a listed team,
        or the reader owns it. One file may be shared with several teams, which an
        enum on the file itself could not express.
        """

        definition = """
        -> File
        principal_type : enum('account','team','public')
        principal      : varchar(80)   # account_id, LabTeam name, or '' if public
        ---
        granted=CURRENT_TIMESTAMP : timestamp
        """

    @schema
    class AccessLog(dj.Manual):
        """Every permission decision, for audit and quota reconciliation.

        High-write and append-only. Kept in the broker's schema so operational
        traffic never touches Spyglass's provenance tables.

        The account reference is nullable because the most audit-worthy event is a
        caller GitHub recognizes but the broker does not, being refused. A
        non-null foreign key would make exactly that row un-writable, so
        `github_id` records who it was when no account can name them.
        """

        definition = """
        log_id      : bigint auto_increment
        ---
        -> [nullable] Account      # null: authenticated, but holds no account
        github_id=null: bigint     # who it was, when there is no account to name
        action      : enum('resolve','read','register','visibility','login')
        file_id=null: char(32)
        granted     : bool
        size_bytes=0: bigint      # charged at URL-issue time; a lower bound
        source_ip   : varchar(45) # IPv6-safe
        timestamp=CURRENT_TIMESTAMP : timestamp
        index (account_id, timestamp)
        """

    return SimpleNamespace(
        Account=Account,
        ClientToken=ClientToken,
        File=File,
        FileAccess=FileAccess,
        AccessLog=AccessLog,
    )
