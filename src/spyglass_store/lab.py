"""Read Spyglass's lab tables without importing Spyglass.

The broker needs two facts from Spyglass: which lab member a GitHub identity
belongs to, and which teams that member is on. It does *not* need Spyglass's
Python classes, which carry mixins, permission checks, and NWB logic irrelevant
here.

`dj.create_virtual_module` reflects an existing schema into table classes at
runtime, which is exactly this situation: attach to tables someone else
declared. Importing `spyglass.common` instead would fail without the full
scientific stack — `common_lab` imports `pynwb` and the `spyglass.utils` mixin
chain, so even a `--no-deps` install raises `ImportError` before reaching
`LabMember`.

Only two columns are read, `lab_member_name` and `team_name`, both stable. A
schema change would surface as a `DataJointError` on first use rather than
silently wrong permissions.
"""

from __future__ import annotations

from functools import lru_cache

import datajoint as dj

#: Spyglass declares this schema with a literal name, not a configured prefix.
LAB_SCHEMA = "common_lab"

#: Every column the broker reads, by the path used to reach it. Reflection
#: resolves at runtime, so an upstream rename would otherwise surface as a
#: failed query mid-request. Checked once at startup instead.
REQUIRED_COLUMNS = {
    ("LabMember", "LabMemberInfo"): ("lab_member_name", "github_user_name"),
    ("LabTeam", "LabTeamMember"): ("lab_member_name", "team_name"),
}


@lru_cache(maxsize=1)
def lab_module():
    """Return the reflected `common_lab` schema.

    Returns
    -------
    types.ModuleType
        Virtual module exposing `LabMember` and `LabTeam`.
    """
    return dj.create_virtual_module(LAB_SCHEMA, LAB_SCHEMA)


def verify_lab_schema() -> None:
    """Check that Spyglass still exposes the columns the broker reads.

    Call once at startup. Turns an upstream schema change into a boot failure
    naming the missing column, rather than a permission query that fails —
    or worse, silently returns nothing — while serving a request.

    Raises
    ------
    RuntimeError
        If a table or column the broker depends on is absent.
    """
    module = lab_module()
    missing = []

    for (master, part), columns in REQUIRED_COLUMNS.items():
        table = getattr(getattr(module, master, None), part, None)
        if table is None:
            missing.append(f"{LAB_SCHEMA}.{master}.{part} (table)")
            continue
        present = set(table.heading.names)
        missing.extend(
            f"{LAB_SCHEMA}.{master}.{part}.{col}"
            for col in columns
            if col not in present
        )

    if missing:
        raise RuntimeError(
            "Spyglass lab schema is missing what the broker reads:\n  "
            + "\n  ".join(missing)
            + "\nThe broker reflects these tables rather than importing "
            + "Spyglass; a rename upstream requires a matching change here."
        )


def lab_member_for_github(github_login: str) -> str | None:
    """Return the lab member linked to a GitHub login.

    Parameters
    ----------
    github_login : str
        GitHub username, as recorded in `LabMember.LabMemberInfo`.

    Returns
    -------
    str or None
        The `lab_member_name`, or None when the login is not linked to one.
        None is normal, not an error: an unaffiliated reader holds a broker
        account with no lab membership.
    """
    query = lab_module().LabMember.LabMemberInfo & {
        "github_user_name": github_login
    }
    names = query.fetch("lab_member_name")

    return names[0] if len(names) else None


def teams_for_member(lab_member_name: str) -> set[str]:
    """Return the names of every team a lab member belongs to.

    Parameters
    ----------
    lab_member_name : str
        Primary key of `LabMember`.

    Returns
    -------
    set of str
        Team names. Empty when the member is on no team.
    """
    query = lab_module().LabTeam.LabTeamMember & {
        "lab_member_name": lab_member_name
    }

    return set(query.fetch("team_name"))


def teams_for_github(github_login: str) -> set[str]:
    """Return the teams a GitHub identity may read through.

    Parameters
    ----------
    github_login : str
        GitHub username.

    Returns
    -------
    set of str
        Team names, empty if the login is unlinked or on no team.
    """
    member = lab_member_for_github(github_login)

    return teams_for_member(member) if member else set()
