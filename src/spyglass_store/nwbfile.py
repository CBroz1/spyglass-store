"""Read Spyglass's file tables without importing Spyglass.

One fact is needed from here: which raw file an analysis file was derived from.
`AnalysisNwbfile` records it as a foreign key to `Nwbfile`, so the broker can
read the relationship rather than infer it.

Reflected with `dj.create_virtual_module` for the same reasons as `lab.py`:
importing `spyglass.common` would drag in pynwb and the rest of a scientific
stack this service exists to keep out.

**Why not the file names.** Spyglass names analysis files after the raw they
came from — `SomePrefix.nwb` becomes `SomePrefix_.nwb` and then
`SomePrefix_{10 random chars}.nwb` — so a parent looks derivable by stripping a
suffix. It is not reliable: a raw file whose own name ends in something shaped
like `_<10 chars>` parses to the wrong prefix, and the failure is silent and in
the wrong direction. The foreign key cannot be wrong.

**Depth is always one.** `AnalysisNwbfile` points at `Nwbfile`, so every
analysis file's parent is a raw file and there is no chain to walk. A result
drawing on several analysis files is a client-side concern, declared through
`share_parents` there; nothing here recurses.

**This table is not a trust root, unlike the lab tables.** Ordinary users insert
into `AnalysisNwbfile` — writing an analysis file is what a pipeline does — so a
row here is a user's claim rather than an administrator's. The broker therefore
reads the edge *once*, when a file is registered, and stores it; see
`registry.register_file`. A live lookup on every read would let someone
re-point the provenance of a registration that already exists.

**Project what you read.** `analysis_file_abs_path` is a `filepath@analysis`
attribute, and fetching it would have DataJoint resolve an external store the
broker has no configuration for. Every query here names its columns.
"""

from __future__ import annotations

from functools import lru_cache

import datajoint as dj

from spyglass_store.db import serialized

#: Spyglass declares this schema with a literal name, not a configured prefix.
NWBFILE_SCHEMA = "common_nwbfile"

#: Every column the broker reads, by the table it lives on. Reflection resolves
#: at runtime, so a rename upstream would otherwise surface as a failed query
#: mid-request. Checked once at startup instead.
REQUIRED_COLUMNS = {
    "Nwbfile": ("nwb_file_name",),
    "AnalysisNwbfile": ("analysis_file_name", "nwb_file_name"),
}


@lru_cache(maxsize=1)
def nwbfile_module():
    """Return the reflected `common_nwbfile` schema.

    Returns
    -------
    types.ModuleType
        Virtual module exposing `Nwbfile` and `AnalysisNwbfile`.
    """
    return dj.create_virtual_module(NWBFILE_SCHEMA, NWBFILE_SCHEMA)


@serialized
def verify_nwbfile_schema() -> None:
    """Check that Spyglass still exposes the columns the broker reads.

    Call once at startup, beside `lab.verify_lab_schema`. Turns an upstream
    schema change into a boot failure naming the missing column, rather than a
    provenance lookup that quietly returns nothing while serving a request —
    which would look exactly like a file with no parent.

    Raises
    ------
    RuntimeError
        If a table or column the broker depends on is absent.
    """
    module = nwbfile_module()
    missing = []

    for name, columns in REQUIRED_COLUMNS.items():
        table = getattr(module, name, None)
        if table is None:
            missing.append(f"{NWBFILE_SCHEMA}.{name} (table)")
            continue
        present = set(table.heading.names)
        missing.extend(
            f"{NWBFILE_SCHEMA}.{name}.{col}"
            for col in columns
            if col not in present
        )

    if missing:
        raise RuntimeError(
            "Spyglass file schema is missing what the broker reads:\n  "
            + "\n  ".join(missing)
            + "\nThe broker reflects these tables rather than importing "
            + "Spyglass; a rename upstream requires a matching change here."
        )


@serialized
def parent_for(spyglass_name: str, file_class: str) -> str | None:
    """Return the raw file an analysis file was derived from.

    Parameters
    ----------
    spyglass_name : str
        Name the file is registered under. For an analysis file this is its
        `analysis_file_name`.
    file_class : str
        Either "raw" or "analysis". A raw file has no parent and is answered
        without a query.

    Returns
    -------
    str or None
        The parent's `nwb_file_name`, or None when there is no parent to find.

        None is not an error. A name Spyglass has no row for is a file the
        broker was asked to store anyway — policing what the instance knows is
        not its job, and refusing the registration would break any workflow
        that shares a file before recording it.
    """
    if file_class != "analysis":
        return None

    query = nwbfile_module().AnalysisNwbfile & {
        "analysis_file_name": spyglass_name
    }
    # One column, named: the row also carries a `filepath@` attribute that
    # would send DataJoint looking for an external store the broker has no
    # configuration for.
    parents = query.fetch("nwb_file_name")

    return str(parents[0]) if len(parents) else None
