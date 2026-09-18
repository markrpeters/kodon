"""The coverage report generates, every rule has a technique, gaps are the
scope minus what the rules tag."""

from __future__ import annotations

import json

from kodon.coverage import coverage_report, load_scope, render_matrix


def test_every_rule_in_scope(rules) -> None:
    report = coverage_report([lr.meta for lr in rules])
    assert not report.out_of_scope, f"tag these in coverage/attack_scope.yml: {report.out_of_scope}"


def test_gaps_are_scope_minus_covered(rules) -> None:
    report = coverage_report([lr.meta for lr in rules])
    scope = {t.technique for t in load_scope()}
    covered = {t for m in (lr.meta for lr in rules) for t in m.techniques}
    assert {g.technique for g in report.gaps} == scope - covered
    assert len(report.covered) + len(report.gaps) == len(report.scope)
    assert report.gaps, "a scope with no gaps is a scope that was written after the rules"


def test_matrix_renders(rules) -> None:
    report = coverage_report([lr.meta for lr in rules])
    text = render_matrix(report)
    assert "GAP" in text and "# T1047" in text
    for lr in rules:
        assert lr.rule_id in text


def test_report_serialises(rules) -> None:
    report = coverage_report([lr.meta for lr in rules])
    data = json.loads(report.model_dump_json())
    assert set(data) >= {"scope", "by_technique", "by_tactic", "out_of_scope"}
