from __future__ import annotations

from pathlib import Path

import pytest

from kodon.loader import LoadedRule, load_rules

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "tests" / "samples"


@pytest.fixture(scope="session")
def rules() -> list[LoadedRule]:
    return load_rules(ROOT / "rules")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "loaded" in metafunc.fixturenames:
        loaded = load_rules(ROOT / "rules")
        metafunc.parametrize("loaded", loaded, ids=[lr.rule_id for lr in loaded])
