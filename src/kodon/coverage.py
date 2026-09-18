"""ATT&CK coverage matrix and gaps, computed against a declared scope."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from kodon.contracts import CoverageReport, RuleMeta, TechniqueRef
from kodon.loader import resource_dir

SCOPE_FILE = "attack_scope.yml"


def load_scope(path: Path | None = None) -> list[TechniqueRef]:
    p = path or resource_dir("coverage") / SCOPE_FILE
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return [TechniqueRef.model_validate(t) for t in data["techniques"]]


def coverage_report(metas: list[RuleMeta], scope: list[TechniqueRef] | None = None) -> CoverageReport:
    scope = scope if scope is not None else load_scope()
    in_scope = {t.technique for t in scope}
    by_technique: dict[str, list[str]] = defaultdict(list)
    by_tactic: dict[str, list[str]] = defaultdict(list)
    out_of_scope: dict[str, list[str]] = defaultdict(list)
    for m in metas:
        for t in m.techniques:
            by_technique[t].append(m.rule_id)
            if t not in in_scope:
                out_of_scope[t].append(m.rule_id)
        for tac in m.tactics:
            by_tactic[tac].append(m.rule_id)
    return CoverageReport(
        scope=scope,
        by_technique=dict(by_technique),
        by_tactic=dict(by_tactic),
        out_of_scope=dict(out_of_scope),
    )


def render_matrix(report: CoverageReport) -> str:
    """Tactic-major text matrix: one line per in-scope technique."""
    tactics: list[str] = []
    for t in report.scope:
        for tac in t.tactics:
            if tac not in tactics:
                tactics.append(tac)
    lines = [
        f"ATT&CK coverage: {len(report.covered)}/{len(report.scope)} in-scope techniques "
        f"have at least one rule; {len(report.gaps)} gaps",
        "",
    ]
    for tac in tactics:
        lines.append(f"[{tac}]")
        for t in report.scope:
            if tac not in t.tactics:
                continue
            rules = report.by_technique.get(t.technique, [])
            mark = "#" if rules else "."
            who = ", ".join(rules) if rules else "GAP"
            lines.append(f"  {mark} {t.technique:<10} {t.name:<44} {who}")
        lines.append("")
    if report.out_of_scope:
        lines.append("tagged but outside the declared scope (add to coverage/attack_scope.yml):")
        for t, rules in sorted(report.out_of_scope.items()):
            lines.append(f"  ? {t:<10} {', '.join(rules)}")
        lines.append("")
    return "\n".join(lines)
