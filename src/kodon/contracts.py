"""The public consumption contract: what a downstream consumer receives.

Everything a consumer needs is a plain pydantic model. pySigma objects never
cross this boundary, so a consumer does not need to know pySigma to use the
hits, and the models can be serialised straight into a finding store.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Status = Literal["experimental", "test", "stable", "deprecated", "unsupported"]
Level = Literal["informational", "low", "medium", "high", "critical"]
RuleKind = Literal["event", "correlation"]


class DetectionHealth(BaseModel):
    """When the rule was added, when a human last looked at it, and who owns it."""

    added: date
    last_reviewed: date
    owner: str

    @field_validator("last_reviewed")
    @classmethod
    def _reviewed_after_added(cls, v: date, info: Any) -> date:
        added = info.data.get("added")
        if added is not None and v < added:
            raise ValueError("last_reviewed precedes added")
        return v


class RuleMeta(BaseModel):
    """Metadata contract enforced by the loader for every rule file."""

    rule_id: str = Field(description="File stem; stable, human-readable identifier")
    sigma_id: str = Field(description="Sigma id: uuid5 of the rule_id, 32 hex chars")
    title: str
    status: Status
    level: Level
    kind: RuleKind
    logsource: dict[str, str]
    techniques: list[str] = Field(description="ATT&CK technique ids, e.g. T1127.001")
    tactics: list[str] = Field(description="ATT&CK tactic slugs, e.g. defense-evasion")
    data_sources: list[str]
    false_positives: list[str]
    do_not_alert_when: str = Field(
        description="The judgment call: when this rule should stay a hunt, not an alert"
    )
    detection_health: DetectionHealth
    references: list[str] = Field(default_factory=list)
    path: str


class DetectionHit(BaseModel):
    """One row that a compiled rule matched. For an event rule this is the
    event; for a correlation rule it is one aggregated group (bucket,
    group-by values, count)."""

    rule_id: str
    sigma_id: str
    title: str
    level: Level
    kind: RuleKind
    techniques: list[str]
    tactics: list[str]
    matched: dict[str, Any]


class TechniqueRef(BaseModel):
    technique: str
    name: str
    tactics: list[str]


class CoverageReport(BaseModel):
    """ATT&CK coverage of the rule set against a declared scope.

    Gaps are computed against the scope, not against all of ATT&CK: a matrix
    that is red everywhere says nothing about what the rule set was meant to
    cover.
    """

    scope: list[TechniqueRef]
    by_technique: dict[str, list[str]] = Field(description="technique id -> rule ids")
    by_tactic: dict[str, list[str]] = Field(description="tactic -> rule ids")
    out_of_scope: dict[str, list[str]] = Field(
        description="techniques tagged by a rule but absent from the scope"
    )

    @property
    def gaps(self) -> list[TechniqueRef]:
        return [t for t in self.scope if not self.by_technique.get(t.technique)]

    @property
    def covered(self) -> list[TechniqueRef]:
        return [t for t in self.scope if self.by_technique.get(t.technique)]
