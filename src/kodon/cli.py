"""kodon validate | compile --target | test | coverage | demo"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from kodon.compile import TARGETS, compile_all, compile_rule
from kodon.coverage import coverage_report, render_matrix
from kodon.loader import LoadedRule, RuleContractError, load_rules
from kodon.replay import replay_samples
from kodon.synth import write_samples


def _samples_dir() -> Path:
    from kodon.loader import repo_root

    root = repo_root()
    if root is not None and (root / "tests" / "samples").is_dir():
        return root / "tests" / "samples"
    raise FileNotFoundError("tests/samples not found; run `kodon demo` or scripts/gen_samples.py")


def _load() -> list[LoadedRule]:
    try:
        return load_rules()
    except RuleContractError as exc:
        print(f"CONTRACT VIOLATION: {exc}", file=sys.stderr)
        sys.exit(2)


def cmd_validate(args: argparse.Namespace) -> int:
    rules = _load()
    print(f"{'rule_id':<42} {'kind':<12} {'level':<8} techniques")
    for lr in rules:
        m = lr.meta
        print(f"{m.rule_id:<42} {m.kind:<12} {m.level:<8} {', '.join(m.techniques)}")
    print(f"\n{len(rules)} rules valid; metadata contract satisfied")
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    rules = _load()
    if args.rule:
        rules = [lr for lr in rules if lr.rule_id == args.rule]
        if not rules:
            print(f"no rule named {args.rule}", file=sys.stderr)
            return 2
    for lr in rules:
        print(f"# {lr.rule_id} [{args.target}]")
        print(compile_rule(lr, args.target))
        print()
    return 0


def _replay_table(rules: list[LoadedRule], samples: Path) -> bool:
    ok = True
    print(f"{'rule_id':<42} {'hit rows':>8} {'matched':>8} {'miss rows':>9} {'matched':>8}  result")
    for lr in rules:
        r = replay_samples(lr, samples)
        ok = ok and r.passed
        print(
            f"{r.rule_id:<42} {r.hit_rows:>8} {r.hit_matches:>8} {r.miss_rows:>9} {r.miss_matches:>8}  "
            f"{'PASS' if r.passed else 'FAIL'}"
        )
    return ok


def cmd_test(args: argparse.Namespace) -> int:
    rules = _load()
    ok = _replay_table(rules, Path(args.samples) if args.samples else _samples_dir())
    print("\nreplay: PASS" if ok else "\nreplay: FAIL")
    return 0 if ok else 1


def cmd_coverage(args: argparse.Namespace) -> int:
    rules = _load()
    report = coverage_report([lr.meta for lr in rules])
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(render_matrix(report))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    print("kodon demo: generate -> validate -> compile -> replay -> coverage (no model, no network)\n")
    rules = _load()
    with tempfile.TemporaryDirectory(prefix="kodon-samples-") as tmp:
        samples = Path(tmp)
        counts = write_samples(samples)
        print(f"[1/5] generated seeded samples for {len(counts)} rules "
              f"({sum(h for h, _ in counts.values())} must-hit rows, {sum(m for _, m in counts.values())} must-miss rows)")
        print(f"[2/5] validated {len(rules)} rules against the metadata contract")
        for target in TARGETS:
            compile_all(rules, target)
        print(f"[3/5] compiled {len(rules)} rules to {', '.join(TARGETS)}")
        example = next(lr for lr in rules if lr.correlation is not None)
        print(f"\n      example, {example.rule_id}:")
        for target in TARGETS:
            body = compile_rule(example, target).strip().replace("\n\n", "\n")
            print(f"      --- {target}\n" + "\n".join("      " + line for line in body.splitlines()))
        print("\n[4/5] replay: compiled DuckDB SQL over the samples")
        ok = _replay_table(rules, samples)
    print("\n[5/5] coverage")
    print(render_matrix(coverage_report([lr.meta for lr in rules])))
    print("demo: PASS" if ok else "demo: FAIL")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kodon", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="load every rule and enforce the metadata contract").set_defaults(fn=cmd_validate)
    c = sub.add_parser("compile", help="print compiled queries")
    c.add_argument("--target", choices=TARGETS, required=True)
    c.add_argument("--rule", help="only this rule id")
    c.set_defaults(fn=cmd_compile)
    t = sub.add_parser("test", help="replay every rule's hit/miss samples")
    t.add_argument("--samples", help="samples directory (default: tests/samples)")
    t.set_defaults(fn=cmd_test)
    cv = sub.add_parser("coverage", help="ATT&CK coverage matrix and gaps")
    cv.add_argument("--json", action="store_true")
    cv.set_defaults(fn=cmd_coverage)
    sub.add_parser("demo", help="generate, validate, compile, replay, coverage").set_defaults(fn=cmd_demo)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
