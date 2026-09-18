#!/usr/bin/env python3
"""Print the ATT&CK coverage matrix (rules -> techniques) and the gaps.

Usage: python scripts/coverage_report.py [--json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kodon.coverage import coverage_report, render_matrix  # noqa: E402
from kodon.loader import load_rules  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = coverage_report([lr.meta for lr in load_rules()])
    print(report.model_dump_json(indent=2) if args.json else render_matrix(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
