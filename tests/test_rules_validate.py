"""Every rule parses as Sigma and satisfies the metadata contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from kodon.loader import RuleContractError, expected_sigma_id, load_rule, load_rules

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DIRS = ("windows", "identity", "network", "email")


def test_rule_tree_has_the_four_domains() -> None:
    for d in REQUIRED_DIRS:
        assert any((ROOT / "rules" / d).glob("*.yml")), f"rules/{d} is empty"


def test_loader_finds_rules(rules) -> None:
    assert len(rules) >= 10


def test_metadata_contract(loaded) -> None:
    m = loaded.meta
    assert m.rule_id == Path(m.path).stem
    assert m.sigma_id == expected_sigma_id(m.rule_id)
    assert len(m.sigma_id) == 32 and "-" not in m.sigma_id
    assert m.techniques and all(t.startswith("T") for t in m.techniques)
    assert m.tactics
    assert m.data_sources
    assert m.false_positives
    assert len(m.do_not_alert_when) > 40, "do_not_alert_when must be a real judgment call"
    assert m.detection_health.owner == "Mark Peters"
    assert m.logsource.get("product")
    assert m.references, "adapted patterns need a public reference"


def test_correlation_rules_are_well_formed(loaded) -> None:
    if loaded.correlation is None:
        return
    assert loaded.meta.kind == "correlation"
    assert loaded.correlation.group_by
    assert loaded.correlation.timespan.seconds > 0


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "broken_rule.yml"
    p.write_text(text, encoding="utf-8")
    return p


BASE = """
title: Broken
id: {id}
status: experimental
date: 2026-09-18
tags: [attack.t1047, attack.execution]
logsource: {{product: windows, category: process_creation}}
detection:
  sel:
    Image|endswith: '\\\\wmic.exe'
  condition: sel
falsepositives: [none]
level: low
custom:
  data_sources: [x]
  do_not_alert_when: never
  detection_health: {{added: 2026-09-18, last_reviewed: 2026-09-18, owner: Mark Peters}}
"""


def test_rejects_wrong_id(tmp_path: Path) -> None:
    p = _write(tmp_path, BASE.format(id="abcdef" * 5 + "ab"))
    with pytest.raises(RuleContractError, match="uuid5"):
        load_rule(p)


def test_rejects_missing_do_not_alert_when(tmp_path: Path) -> None:
    good = expected_sigma_id("broken_rule")
    p = _write(tmp_path, BASE.format(id=good).replace("  do_not_alert_when: never\n", ""))
    with pytest.raises(RuleContractError, match="do_not_alert_when"):
        load_rule(p)


def test_rejects_missing_technique_tag(tmp_path: Path) -> None:
    good = expected_sigma_id("broken_rule")
    p = _write(tmp_path, BASE.format(id=good).replace("attack.t1047, ", ""))
    with pytest.raises(RuleContractError, match="attack.tNNNN"):
        load_rule(p)


def test_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    good = expected_sigma_id("broken_rule")
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "broken_rule.yml").write_text(BASE.format(id=good), encoding="utf-8")
    with pytest.raises(RuleContractError, match="duplicate"):
        load_rules(tmp_path)
