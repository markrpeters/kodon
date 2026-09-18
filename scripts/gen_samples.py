#!/usr/bin/env python3
"""Regenerate tests/samples from the seeded generator (kodon.synth).

Usage: python scripts/gen_samples.py [--out tests/samples] [--seed N]
The committed samples must equal the generator's output; tests check this.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kodon.synth import SEED, write_samples  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "tests" / "samples"))
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()
    counts = write_samples(Path(args.out), args.seed)
    for rule_id, (h, m) in counts.items():
        print(f"{rule_id:<42} hit={h:<4} miss={m}")
    print(f"wrote samples for {len(counts)} rules to {args.out} (seed {args.seed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
