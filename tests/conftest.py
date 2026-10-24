"""Shared, local-only test fixtures."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _no_network_dependency_check(monkeypatch):
    """Scans in tests never download osv-scanner or query OSV; dependency tests opt back in."""
    monkeypatch.setenv("HERMES_SECURITY_DEPENDENCY_CHECK", "off")


@pytest.fixture
def tmp_data_dir(tmp_path):
    data_dir = tmp_path / "plugin-data" / "hermes-security"
    data_dir.mkdir(parents=True, mode=0o700)
    return data_dir
