import packaging.version

import spyglass_store


def test_version_is_valid() -> None:
    _ = packaging.version.parse(spyglass_store.__version__)


def test_datajoint_matches_the_spyglass_pin() -> None:
    """The broker must speak the DataJoint that Spyglass instances run.

    It reflects `common_lab` from a Spyglass-managed database, and 2.0 renamed
    the API used to do that (`create_virtual_module`, `dj.schema`) as well as
    replacing `dj.config`. An environment that drifted past the pin would fail
    at import, not at test time, so pin the runtime as well as the dependency.
    """
    import datajoint

    version = packaging.version.parse(datajoint.__version__)

    assert version < packaging.version.parse("2.0"), (
        f"datajoint {version} is past the Spyglass pin (<2.0); "
        "see pyproject.toml"
    )
