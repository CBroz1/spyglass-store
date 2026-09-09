import packaging.version

import spyglass_store


def test_version_is_valid() -> None:
    _ = packaging.version.parse(spyglass_store.__version__)
