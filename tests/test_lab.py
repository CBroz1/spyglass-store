"""Tests for reading Spyglass's lab tables via a reflected schema.

No live database: `lab_module` is replaced with a stub that records the
restrictions it is given, which is enough to pin the query shape.
"""

from unittest.mock import patch

import pytest

from spyglass_store import lab


class _Query:
    """Stands in for a restricted DataJoint query."""

    def __init__(self, rows: list[dict]):
        self._rows = rows

    def fetch(self, attr: str) -> list:
        return [r[attr] for r in self._rows]


class _Table:
    """Records the restriction it received, then returns canned rows."""

    def __init__(self, rows: list[dict]):
        self._rows = rows
        self.restrictions: list[dict] = []

    def __and__(self, restriction: dict) -> _Query:
        self.restrictions.append(restriction)
        matched = [
            r
            for r in self._rows
            if all(r.get(k) == v for k, v in restriction.items())
        ]
        return _Query(matched)


@pytest.fixture
def fake_lab():
    """Patch the reflected module with in-memory lab tables."""

    class LabMember:
        LabMemberInfo = _Table(
            [
                {"lab_member_name": "Ada L", "github_user_name": "ada"},
                {"lab_member_name": "Alan T", "github_user_name": "alan"},
            ]
        )

    class LabTeam:
        LabTeamMember = _Table(
            [
                {"lab_member_name": "Ada L", "team_name": "analysis"},
                {"lab_member_name": "Ada L", "team_name": "seizure"},
                {"lab_member_name": "Alan T", "team_name": "seizure"},
            ]
        )

    class Module:
        pass

    module = Module()
    module.LabMember = LabMember
    module.LabTeam = LabTeam

    with patch.object(lab, "lab_module", return_value=module):
        yield module


def test_github_login_resolves_to_a_lab_member(fake_lab) -> None:
    assert lab.lab_member_for_github("ada") == "Ada L"


def test_unlinked_login_is_none_not_an_error(fake_lab) -> None:
    """An unaffiliated reader is a valid account, not a failure."""
    assert lab.lab_member_for_github("stranger") is None


def test_member_teams_are_collected(fake_lab) -> None:
    assert lab.teams_for_member("Ada L") == {"analysis", "seizure"}


def test_member_on_no_team_yields_empty_set(fake_lab) -> None:
    assert lab.teams_for_member("Grace H") == set()


def test_github_to_teams_end_to_end(fake_lab) -> None:
    assert lab.teams_for_github("alan") == {"seizure"}


def test_unlinked_login_grants_no_teams(fake_lab) -> None:
    """The path that matters: an unknown identity must not inherit access."""
    assert lab.teams_for_github("stranger") == set()


def test_queries_restrict_on_the_expected_columns(fake_lab) -> None:
    """Pins the two columns the broker depends on.

    A Spyglass schema change to either would break the broker, so the
    dependency is made explicit rather than implied.
    """
    lab.teams_for_github("ada")

    assert fake_lab.LabMember.LabMemberInfo.restrictions == [
        {"github_user_name": "ada"}
    ]
    assert fake_lab.LabTeam.LabTeamMember.restrictions == [
        {"lab_member_name": "Ada L"}
    ]


def test_schema_name_is_not_configurable() -> None:
    """Spyglass declares `common_lab` literally, so the broker matches it."""
    assert lab.LAB_SCHEMA == "common_lab"
