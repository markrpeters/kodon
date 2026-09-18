"""Load rule files and enforce the metadata contract.

A rule file is one Sigma rule, optionally followed (in the same YAML file) by
one Sigma correlation rule that references it. The file stem is the rule id.
The Sigma `id` is not invented: it must equal uuid5(NAMESPACE_URL,
"kodon:<rule_id>") in 32-character hex form, so ids are reproducible and the
loader can check them.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from kodon.contracts import DetectionHealth, RuleMeta

RULE_SUFFIXES = (".yml", ".yaml")
REQUIRED_CUSTOM = ("data_sources", "do_not_alert_when", "detection_health")
SUPPORTED_CORRELATIONS = ("event_count", "value_count")


class RuleContractError(ValueError):
    """A rule file violates the metadata contract."""


@dataclass
class LoadedRule:
    meta: RuleMeta
    rule: SigmaRule
    correlation: SigmaCorrelationRule | None
    collection: SigmaCollection
    path: Path

    @property
    def rule_id(self) -> str:
        return self.meta.rule_id


def expected_sigma_id(rule_id: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"kodon:{rule_id}").hex


def repo_root() -> Path | None:
    """The checkout that contains this package, if we are running from one."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "rules").is_dir() and (parent / "pyproject.toml").is_file():
            return parent
    return None


def resource_dir(name: str) -> Path:
    """Resolve a content directory (rules, pipelines, coverage).

    Order: KODON_<NAME> environment variable, the directory inside the
    installed package (a built wheel carries them), then the repository
    checkout that this source file lives in.
    """
    env = os.environ.get(f"KODON_{name.upper()}")
    if env:
        return Path(env)
    packaged = Path(__file__).resolve().parent / name
    if packaged.is_dir():
        return packaged
    root = repo_root()
    if root is not None and (root / name).is_dir():
        return root / name
    raise FileNotFoundError(f"cannot locate the '{name}' directory; set KODON_{name.upper()}")


def rule_files(rules_dir: Path | None = None) -> list[Path]:
    base = rules_dir or resource_dir("rules")
    return sorted(p for p in base.rglob("*") if p.suffix in RULE_SUFFIXES and p.is_file())


def _tags(rule: SigmaRule) -> tuple[list[str], list[str]]:
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in rule.tags:
        if tag.namespace != "attack":
            continue
        name = tag.name
        if name[:1] == "t" and name[1:].replace(".", "").isdigit():
            techniques.append(name.upper())
        else:
            tactics.append(name)
    return techniques, tactics


def load_rule(path: Path) -> LoadedRule:
    text = path.read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if d]
    collection = SigmaCollection.from_yaml(text)
    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if len(rules) != 1 or len(correlations) > 1:
        raise RuleContractError(
            f"{path}: expected one Sigma rule and at most one correlation rule, "
            f"got {len(rules)} and {len(correlations)}"
        )
    rule = rules[0]
    correlation = correlations[0] if correlations else None
    if correlation is not None:
        ctype = correlation.type.name.lower()
        if ctype not in SUPPORTED_CORRELATIONS:
            raise RuleContractError(
                f"{path}: correlation type {ctype!r} is not one of {SUPPORTED_CORRELATIONS}"
            )
        referenced = [ref.rule for ref in correlation.rules]
        if referenced != [rule]:
            raise RuleContractError(f"{path}: the correlation must reference the rule in the same file")
        if correlation.generate:
            raise RuleContractError(f"{path}: correlation must not set generate: true")
        if not correlation.group_by:
            raise RuleContractError(f"{path}: correlation needs group-by")
    if rule.errors:
        raise RuleContractError(f"{path}: {rule.errors}")

    rule_id = path.stem
    if rule.id is None:
        raise RuleContractError(f"{path}: missing id")
    expected = expected_sigma_id(rule_id)
    if rule.id.hex != expected:
        raise RuleContractError(
            f"{path}: id must be uuid5 of the rule id: expected {expected}, got {rule.id.hex}"
        )
    raw_id = str(docs[0].get("id", ""))
    if raw_id != expected:
        raise RuleContractError(f"{path}: id must be written as 32 hex characters ({expected})")
    if rule.status is None or rule.level is None:
        raise RuleContractError(f"{path}: status and level are required")
    if rule.date is None:
        raise RuleContractError(f"{path}: date is required")

    techniques, tactics = _tags(rule)
    if not techniques:
        raise RuleContractError(f"{path}: at least one attack.tNNNN tag is required")
    if not tactics:
        raise RuleContractError(f"{path}: at least one attack.<tactic> tag is required")

    custom = rule.custom_attributes.get("custom")
    if not isinstance(custom, dict):
        raise RuleContractError(f"{path}: missing custom: block")
    missing = [k for k in REQUIRED_CUSTOM if k not in custom]
    if missing:
        raise RuleContractError(f"{path}: custom block missing {missing}")
    if not str(custom["do_not_alert_when"]).strip():
        raise RuleContractError(f"{path}: do_not_alert_when must not be empty")
    if not rule.falsepositives:
        raise RuleContractError(f"{path}: falsepositives must list at least one benign trigger")

    logsource = {
        k: v
        for k, v in (
            ("product", rule.logsource.product),
            ("category", rule.logsource.category),
            ("service", rule.logsource.service),
        )
        if v
    }
    meta = RuleMeta(
        rule_id=rule_id,
        sigma_id=expected,
        title=rule.title,
        status=str(rule.status).lower(),
        level=str(rule.level).lower(),
        kind="correlation" if correlation is not None else "event",
        logsource=logsource,
        techniques=techniques,
        tactics=tactics,
        data_sources=[str(x) for x in custom["data_sources"]],
        false_positives=[str(x) for x in rule.falsepositives],
        do_not_alert_when=str(custom["do_not_alert_when"]).strip(),
        detection_health=DetectionHealth.model_validate(custom["detection_health"]),
        references=[str(r) for r in rule.references],
        path=str(path),
    )
    return LoadedRule(meta=meta, rule=rule, correlation=correlation, collection=collection, path=path)


def load_rules(rules_dir: Path | None = None) -> list[LoadedRule]:
    loaded = [load_rule(p) for p in rule_files(rules_dir)]
    seen: dict[str, Path] = {}
    for lr in loaded:
        if lr.rule_id in seen:
            raise RuleContractError(f"duplicate rule id {lr.rule_id}: {seen[lr.rule_id]} and {lr.path}")
        seen[lr.rule_id] = lr.path
    if not loaded:
        raise RuleContractError("no rules found")
    return loaded
