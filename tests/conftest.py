"""Shared, local-only test fixtures."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def tmp_data_dir(tmp_path):
    data_dir = tmp_path / "plugin-data" / "hermes-security"
    data_dir.mkdir(parents=True, mode=0o700)
    return data_dir
