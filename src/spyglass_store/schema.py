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

import datajoint as dj

from spyglass_store.settings import get_settings

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
    created=CURRENT_TIMESTAMP : timestamp
    unique index (github_id)
    """


@schema
class File(dj.Manual):
    """A registered object, addressed by content hash."""

    definition = """
    file_id       : char(32)      # opaque handle used in URLs
    ---
    sha256        : char(64)      # content address; determines the object key
    size_bytes    : bigint
    spyglass_name : varchar(255)  # name the client knows it by
    file_class    : enum('raw','analysis')
    -> Account.proj(owner='account_id')
    registered=CURRENT_TIMESTAMP : timestamp
    index (sha256)
    index (spyglass_name)
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
    """

    definition = """
    log_id      : bigint auto_increment
    ---
    -> Account
    action      : enum('resolve','read','register','visibility','login')
    file_id=null: char(32)
    granted     : bool
    size_bytes=0: bigint      # charged at URL-issue time; a lower bound
    source_ip   : varchar(45) # IPv6-safe
    timestamp=CURRENT_TIMESTAMP : timestamp
    index (account_id, timestamp)
    """
