"""Tests for the startup schema check.

Reflection resolves at runtime, so an upstream rename would otherwise surface
mid-request. These pin that it surfaces at boot instead, naming the column.
"""

from unittest.mock import patch

import pytest

from spyglass_store import lab


class _Heading:
    def __init__(self, names):
        self.names = names


class _Table:
    def __init__(self, *names):
        self.heading = _Heading(list(names))


def build_module(member_cols=None, team_cols=None, drop=()):
    """Assemble a stand-in for the reflected schema."""
    member_cols = member_cols or ("lab_member_name", "github_user_name")
    team_cols = team_cols or ("lab_member_name", "team_name")

    class LabMember:
        pass

    class LabTeam:
        pass

    if "LabMemberInfo" not in drop:
        LabMember.LabMemberInfo = _Table(*member_cols)
    if "LabTeamMember" not in drop:
        LabTeam.LabTeamMember = _Table(*team_cols)

    module = type("Module", (), {})()
    module.LabMember = LabMember
    module.LabTeam = LabTeam
    return module


def test_healthy_schema_passes_quietly() -> None:
    with patch.object(lab, "lab_module", return_value=build_module()):
        lab.verify_lab_schema()  # no raise


def test_renamed_column_is_named_in_the_error() -> None:
    """The message has to say which column, or the operator is left guessing."""
    module = build_module(member_cols=("lab_member_name", "github_handle"))

    with patch.object(lab, "lab_module", return_value=module):
        with pytest.raises(RuntimeError, match="github_user_name"):
            lab.verify_lab_schema()


def test_missing_part_table_is_reported() -> None:
    module = build_module(drop=("LabTeamMember",))

    with patch.object(lab, "lab_module", return_value=module):
        with pytest.raises(RuntimeError, match=r"LabTeam\.LabTeamMember"):
            lab.verify_lab_schema()


def test_every_problem_is_reported_at_once() -> None:
    """One boot, one full list; not a fix-and-rerun loop."""
    module = build_module(
        member_cols=("lab_member_name",), team_cols=("team_name",)
    )

    with patch.object(lab, "lab_module", return_value=module):
        with pytest.raises(RuntimeError) as err:
            lab.verify_lab_schema()

    message = str(err.value)
    assert "github_user_name" in message
    assert "lab_member_name" in message


def test_error_explains_the_reflection_coupling() -> None:
    """Points the reader at why this repo cares about a Spyglass rename."""
    module = build_module(drop=("LabMemberInfo", "LabTeamMember"))

    with patch.object(lab, "lab_module", return_value=module):
        with pytest.raises(RuntimeError, match="reflects these tables"):
            lab.verify_lab_schema()


def test_required_columns_are_the_documented_two_pairs() -> None:
    """Guards scope creep: more columns means more upstream coupling."""
    assert lab.REQUIRED_COLUMNS == {
        ("LabMember", "LabMemberInfo"): (
            "lab_member_name",
            "github_user_name",
        ),
        ("LabTeam", "LabTeamMember"): ("lab_member_name", "team_name"),
    }
