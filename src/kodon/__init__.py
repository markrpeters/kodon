"""kodon: detection-as-code. Sigma rules with tests, compiled to Splunk SPL,
Sentinel KQL and DuckDB SQL, replay-tested on synthetic telemetry.

Public consumption contract (what a downstream pipeline imports):

    from kodon import load_rules, compile_rule, replay, coverage_report
    from kodon.contracts import RuleMeta, DetectionHit, CoverageReport
"""

from kodon.compile import TARGETS, compile_all, compile_rule
from kodon.contracts import CoverageReport, DetectionHit, RuleMeta
from kodon.coverage import coverage_report
from kodon.loader import LoadedRule, load_rules
from kodon.replay import replay

__version__ = "0.0.1"

__all__ = [
    "TARGETS",
    "CoverageReport",
    "DetectionHit",
    "LoadedRule",
    "RuleMeta",
    "__version__",
    "compile_all",
    "compile_rule",
    "coverage_report",
    "load_rules",
    "replay",
]
