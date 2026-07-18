# Anteumbra: inject project root into sys.path for all tests
import sys
from pathlib import Path

import pytest

_root = Path(__file__).parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))


@pytest.fixture(autouse=True)
def clear_repository_caches_between_tests():
    """Do not let process-wide SQLite connections leak locks across tests."""
    from anteumbra.infrastructure.persistence import clear_repository_cache

    clear_repository_cache()
    yield
    clear_repository_cache()
