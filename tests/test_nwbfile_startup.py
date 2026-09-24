"""Tests for the startup check on Spyglass's file tables.

Same shape as `test_lab_startup.py`, and for the same reason: reflection
resolves at runtime, so a rename upstream would otherwise surface mid-request.
Here it would surface as a file with no parent — indistinguishable from a raw
file, and silently the permissive answer — which is the worst way to find out.
"""

from unittest.mock import patch

import pytest

from spyglass_store import nwbfile


class _Heading:
    def __init__(self, names):
        self.names = names


class _Table:
    def __init__(self, *names):
        self.heading = _Heading(list(names))


def build_module(raw_cols=None, analysis_cols=None, drop=()):
    """Assemble a stand-in for the reflected schema."""
    raw_cols = raw_cols or ("nwb_file_name",)
    analysis_cols = analysis_cols or ("analysis_file_name", "nwb_file_name")

    module = type("Module", (), {})()

    if "Nwbfile" not in drop:
        module.Nwbfile = _Table(*raw_cols)
    if "AnalysisNwbfile" not in drop:
        module.AnalysisNwbfile = _Table(*analysis_cols)

    return module


def test_healthy_schema_passes_quietly() -> None:
    with patch.object(nwbfile, "nwbfile_module", return_value=build_module()):
        nwbfile.verify_nwbfile_schema()  # no raise


def test_a_renamed_parent_column_is_named_in_the_error() -> None:
    """`nwb_file_name` on `AnalysisNwbfile` *is* the provenance edge.

    Lose it and every analysis file looks parentless, so the message has to say
    which column rather than leaving an operator to guess why inheritance
    stopped working.
    """
    module = build_module(analysis_cols=("analysis_file_name", "session_id"))

    with patch.object(nwbfile, "nwbfile_module", return_value=module):
        with pytest.raises(RuntimeError, match="nwb_file_name"):
            nwbfile.verify_nwbfile_schema()


def test_a_missing_table_is_reported() -> None:
    """An instance without these tables cannot serve provenance at all."""
    module = build_module(drop=("AnalysisNwbfile",))

    with patch.object(nwbfile, "nwbfile_module", return_value=module):
        with pytest.raises(RuntimeError, match="AnalysisNwbfile"):
            nwbfile.verify_nwbfile_schema()


def test_the_error_names_the_schema_it_reflects() -> None:
    """Two reflected schemas now, so the message has to say which one."""
    module = build_module(drop=("Nwbfile",))

    with patch.object(nwbfile, "nwbfile_module", return_value=module):
        with pytest.raises(RuntimeError, match="common_nwbfile"):
            nwbfile.verify_nwbfile_schema()


def test_a_raw_file_needs_no_lookup() -> None:
    """Asked about a raw file, it answers without touching the database.

    Every registration goes through this, so the common case must not cost a
    query — and a broker serving an instance whose tables are unreachable can
    still register raw files.
    """
    with patch.object(nwbfile, "nwbfile_module", side_effect=AssertionError):
        assert nwbfile.parent_for("session_.nwb", "raw") is None
