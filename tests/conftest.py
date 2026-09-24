"""Fixtures backing the broker's tests with a real MySQL server.

Most of the suite needs no database: permission decisions are pure functions
and the routes take injected fakes. What genuinely needs a server is anything
that writes — registration and visibility — and anything that reflects
Spyglass's lab tables, since reflection is precisely the thing a fake cannot
exercise.

The `db` fixture points DataJoint and the broker settings at the container,
then clears the caches that would otherwise pin the previous values. The
schema declares itself on first use rather than on import, so nothing here has
to control when a module is imported.

Spyglass's `common_lab` is created here rather than mocked. The broker reaches
it through `dj.create_virtual_module`, and reflection against a table that does
not exist is the failure mode `verify_lab_schema` exists to catch — so the
tables have to be real for the check to mean anything.
"""

from __future__ import annotations

import os

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
    parser.addoption(
        "--container-vol-dir",
        action="store",
        default=os.environ.get("SPYGLASS_STORE_DOCKER_VOL_DIR"),
        help="Parent directory for container data, bind-mounted as "
        "<dir>/<container-name>. Keeps MySQL and the object store off the "
        "root disk, which is usually the one that runs out. Defaults to "
        "$SPYGLASS_STORE_DOCKER_VOL_DIR.",
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

    server = MySQLContainer(
        keep=request.config.getoption("--keep-container"),
        vol_dir=request.config.getoption("--container-vol-dir"),
    )
    # Registered before `wait`, which raises on a container that will never
    # become healthy. Without this, that raise happens before the yield, the
    # teardown never runs, and the broken container poisons every later run
    # until someone removes it by hand.
    request.addfinalizer(server.stop)
    server.start()
    server.wait()

    yield server


@pytest.fixture(scope="session")
def s3_server(request):
    """A running S3 store, or a skip if Docker is unavailable.

    Separate from the MySQL fixture so a test needing only one pays for only
    one, and so a missing Docker skips both with the same message.
    """
    docker = pytest.importorskip(
        "docker", reason="object store tests need the docker SDK"
    )

    from tests.container import S3Container

    try:
        docker.from_env()
    except Exception as err:  # daemon down, no socket, no permission
        pytest.skip(f"Docker is not usable: {err}")

    server = S3Container(
        keep=request.config.getoption("--keep-container"),
        vol_dir=request.config.getoption("--container-vol-dir"),
    )
    request.addfinalizer(server.stop)  # see the MySQL fixture
    server.start()
    server.wait()
    server.create_bucket()
    # A kept container carries objects from the last run, and content
    # addressing means a leftover silently turns the next registration into a
    # deduplicated one. Start every session from an empty bucket.
    server.empty_bucket()

    yield server


@pytest.fixture
def s3_settings(s3_server):
    """`Settings` pointed at the container, with a short presign lifetime."""
    from spyglass_store.settings import Settings

    return Settings(presigned_ttl_seconds=300, **s3_server.settings_kwargs())


@pytest.fixture
def object_store(s3_settings):
    """A real `S3ObjectStore` against the container, emptied afterwards.

    Nothing here is faked: boto3 signs, the store verifies, and bytes move over
    HTTP. That is the whole point — presigning is exactly the behaviour a
    stub cannot stand in for.

    The bucket is cleared between tests because the container is session
    scoped and objects are content addressed. A leftover object makes the
    next registration of the same bytes deduplicate, so a test would silently
    exercise the cached path instead of the one it names.
    """
    from spyglass_store.s3 import S3ObjectStore

    store = S3ObjectStore(s3_settings)

    yield store

    _empty_bucket(store._client, s3_settings.s3_bucket)


def _empty_bucket(client, bucket: str) -> None:
    """Delete every object in `bucket`."""
    listed = client.list_objects_v2(Bucket=bucket)

    keys = [{"Key": obj["Key"]} for obj in listed.get("Contents", [])]

    if keys:
        client.delete_objects(Bucket=bucket, Delete={"Objects": keys})


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

    from spyglass_store import lab, schema
    from spyglass_store.settings import get_settings

    def reset():
        get_settings.cache_clear()
        lab.lab_module.cache_clear()
        schema.get_schema.cache_clear()

    reset()
    _declare_lab_schema(dj)
    _declare_nwbfile_schema(dj)

    yield schema.get_schema()

    reset()


def _declare_lab_schema(dj) -> None:
    """Create the two Spyglass tables the broker reflects.

    Only the columns in `lab.REQUIRED_COLUMNS` matter; the rest are included
    so the shape matches what Spyglass actually declares.

    The schema is named literally `common_lab`, and teardown deletes from it.
    Pointed at the wrong host that is a production accident, so the host is
    asserted first rather than trusted to whatever configured it.
    """
    host = str(dj.config["database.host"])

    if host not in {"127.0.0.1", "localhost"}:
        raise RuntimeError(
            f"Refusing to declare {lab_module_name()!r} against {host!r}. "
            "These fixtures create and delete Spyglass's own lab tables, so "
            "they may only run against a local test container."
        )

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


def _declare_nwbfile_schema(dj) -> None:
    """Create the two Spyglass file tables the broker reflects.

    The broker reads one fact from these: which raw file an analysis file was
    derived from. `AnalysisNwbfile` records it as a foreign key, which is why
    the broker reflects the table rather than parsing file names.

    **The `filepath@` attributes are deliberately omitted.** Spyglass declares
    `nwb_file_abs_path` and `analysis_file_abs_path` as external filepath
    stores, and declaring them here would need store configuration the broker
    has none of. Leaving them out also means a query in the broker that fetched
    a whole row — rather than naming the column it wants — fails in this suite
    instead of only in production.

    Same host guard as `_declare_lab_schema`, for the same reason: this creates
    and drops tables under Spyglass's own schema name.
    """
    host = str(dj.config["database.host"])

    if host not in {"127.0.0.1", "localhost"}:
        raise RuntimeError(
            f"Refusing to declare {nwbfile_module_name()!r} against {host!r}. "
            "These fixtures create and delete Spyglass's own file tables, so "
            "they may only run against a local test container."
        )

    nwb_schema = dj.schema(nwbfile_module_name())

    @nwb_schema
    class Nwbfile(dj.Manual):
        definition = """
        nwb_file_name : varchar(64)
        """

    @nwb_schema
    class AnalysisNwbfile(dj.Manual):
        definition = """
        analysis_file_name : varchar(64)
        ---
        -> Nwbfile
        analysis_file_description='' : varchar(2000)
        """


def nwbfile_module_name() -> str:
    """Return the schema name Spyglass declares its file tables under."""
    from spyglass_store.nwbfile import NWBFILE_SCHEMA

    return NWBFILE_SCHEMA


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
def nwbfile_tables(db):
    """Empty `Nwbfile` and `AnalysisNwbfile`, refilled per test.

    Yields
    ------
    tuple
        `(Nwbfile, AnalysisNwbfile)` from the reflected module.
    """
    from spyglass_store.nwbfile import nwbfile_module

    module = nwbfile_module()

    yield module.Nwbfile, module.AnalysisNwbfile

    module.AnalysisNwbfile.delete_quick()
    module.Nwbfile.delete_quick()


@pytest.fixture
def broker_tables(db):
    """Empty broker tables, cleared after each test.

    Yields
    ------
    tuple
        `(Account, File, FileAccess)`.
    """
    yield db.Account, db.File, db.FileAccess

    db.AccessLog.delete_quick()
    db.ClientToken.delete_quick()
    db.FileAccess.delete_quick()
    db.File.delete_quick()
    db.Account.delete_quick()
