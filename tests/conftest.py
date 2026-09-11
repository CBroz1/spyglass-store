"""Fixtures backing the broker's tests with a real MySQL server.

Most of the suite needs no database: permission decisions are pure functions
and the routes take injected fakes. What genuinely needs a server is anything
that writes — registration and visibility — and anything that reflects
Spyglass's lab tables, since reflection is precisely the thing a fake cannot
exercise.

Ordering matters more than usual here. `schema.py` calls `dj.schema()` at
import time using a cached `Settings`, so the schema prefix and the DataJoint
connection must both be set *before* anything imports it. The `db` fixture does
that and then clears the caches that would otherwise pin the old values.

Spyglass's `common_lab` is created here rather than mocked. The broker reaches
it through `dj.create_virtual_module`, and reflection against a table that does
not exist is the failure mode `verify_lab_schema` exists to catch — so the
tables have to be real for the check to mean anything.
"""

from __future__ import annotations

import pytest

#: Schema prefix for the broker's own tables. Distinct from the deployed
#: default so a misconfigured run cannot land on a real schema.
TEST_PREFIX = "test_store"


def pytest_addoption(parser):
    """Add container-control flags."""
    parser.addoption(
        "--keep-container",
        action="store_true",
        default=False,
        help="Leave the MySQL container running after the session, so the "
        "next run skips startup. Data persists; use for iterating.",
    )


@pytest.fixture(scope="session")
def container(request):
    """A running MySQL server, or a skip if Docker is unavailable."""
    docker = pytest.importorskip(
        "docker", reason="database tests need the docker SDK"
    )

    from tests.container import MySQLContainer

    try:
        docker.from_env()
    except Exception as err:  # daemon down, no socket, no permission
        pytest.skip(f"Docker is not usable: {err}")

    server = MySQLContainer(keep=request.config.getoption("--keep-container"))
    server.start()
    server.wait()

    yield server

    server.stop()


@pytest.fixture(scope="session")
def db(container, monkeypatch_session):
    """Point DataJoint and the broker settings at the container.

    Yields
    ------
    module
        `spyglass_store.schema`, imported only once the connection and prefix
        are in place.
    """
    import datajoint as dj

    dj.config.update(container.credentials)
    dj.conn(reset=True)

    monkeypatch_session.setenv("SPYGLASS_STORE_SCHEMA_PREFIX", TEST_PREFIX)

    from spyglass_store import lab, registry
    from spyglass_store.settings import get_settings

    get_settings.cache_clear()
    lab.lab_module.cache_clear()
    registry.tables.cache_clear()

    _declare_lab_schema(dj)

    from spyglass_store import schema

    yield schema

    get_settings.cache_clear()
    lab.lab_module.cache_clear()
    registry.tables.cache_clear()


def _declare_lab_schema(dj) -> None:
    """Create the two Spyglass tables the broker reflects.

    Only the columns in `lab.REQUIRED_COLUMNS` matter; the rest are included
    so the shape matches what Spyglass actually declares.
    """
    lab_schema = dj.schema(lab_module_name())

    @lab_schema
    class LabMember(dj.Manual):
        definition = """
        lab_member_name : varchar(80)
        """

        class LabMemberInfo(dj.Part):
            definition = """
            -> master
            ---
            google_user_name='' : varchar(200)
            datajoint_user_name='' : varchar(64)
            github_user_name='' : varchar(200)
            """

    @lab_schema
    class LabTeam(dj.Manual):
        definition = """
        team_name : varchar(80)
        """

        class LabTeamMember(dj.Part):
            definition = """
            -> master
            -> LabMember
            """


def lab_module_name() -> str:
    """Return the schema name Spyglass declares its lab tables under."""
    from spyglass_store.lab import LAB_SCHEMA

    return LAB_SCHEMA


@pytest.fixture(scope="session")
def monkeypatch_session():
    """A session-scoped `monkeypatch`.

    The built-in fixture is function-scoped, and the environment has to stay
    patched for as long as the schema module is imported.
    """
    from _pytest.monkeypatch import MonkeyPatch

    patcher = MonkeyPatch()

    yield patcher

    patcher.undo()


@pytest.fixture
def lab_tables(db):
    """Empty lab tables, refilled per test.

    Yields
    ------
    tuple
        `(LabMember, LabTeam)` from the reflected module.
    """
    from spyglass_store.lab import lab_module

    module = lab_module()

    yield module.LabMember, module.LabTeam

    module.LabTeam.LabTeamMember.delete_quick()
    module.LabTeam.delete_quick()
    module.LabMember.LabMemberInfo.delete_quick()
    module.LabMember.delete_quick()


@pytest.fixture
def broker_tables(db):
    """Empty broker tables, cleared after each test.

    Yields
    ------
    tuple
        `(Account, File, FileAccess)`.
    """
    yield db.Account, db.File, db.FileAccess

    db.FileAccess.delete_quick()
    db.File.delete_quick()
    db.Account.delete_quick()
