"""Reject test sessions that resolve Anteumbra outside the source tree."""

from pathlib import Path

import anteumbra


SOURCE_PACKAGE = (Path(__file__).parent / "src" / "anteumbra").resolve()
IMPORTED_PACKAGE = Path(anteumbra.__file__).resolve()

if not IMPORTED_PACKAGE.is_relative_to(SOURCE_PACKAGE):
    raise RuntimeError(
        "Tests must import Anteumbra from the repository source tree, got "
        f"{IMPORTED_PACKAGE}"
    )
