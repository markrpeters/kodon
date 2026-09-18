# CLAUDE.md — Kodon

## What Kodon is
Detection-as-code: Sigma rules compiled to Splunk SPL, Microsoft Sentinel KQL, and DuckDB SQL, replay-tested on seeded synthetic telemetry, with an ATT&CK coverage report and CI gates. Kodon is a public artifact and a real dependency: a separate private forensics pipeline imports it as a Detect stage. Governing design: WO-008.

## Hard constraints (never violate; stop and ask if in doubt)
- One-way dependency. This repo knows nothing about any private repo, employer, cloud account, customer, schema, hostname, case, or dataset. Nothing private is read, referenced, or tested against here.
- Zero real telemetry. All samples come from scripts/gen_samples.py (seeded; RFC-5737 IPs, RFC-2606 domains, HOST-A/B/C hosts, invented users). Never paste sample data from memory.
- The identifier scan gate (scripts/ip_scan.sh via pre-commit and CI) runs on every commit. If it fails, the commit does not happen. Do not bypass it.
- Commits are authored by the maintainer only. No Co-Authored-By or tool-session trailers. The build methodology is disclosed once, in the README.
- No bulk import of public rule sets. Rules are written from named patterns; adapted rules carry attribution.
- A rule without a must-hit and a must-not-hit sample does not merge. A rule without `do_not_alert_when` does not validate.

## Working style
- Propose before implementing anything that changes structure, a contract, or a rule's semantics: one short design note with the tradeoff, then wait for approval. Small, obvious changes: do them and say what changed.
- Explain the why in one or two sentences per meaningful change, naming the concept when one applies (processing pipeline, logsource, modifier, backend, field mapping).
- When emitting compiled SPL or KQL, note one idiom in it worth knowing and how it differs in the other dialect.
- Tests first or alongside; never after.
- Run the full gate set before declaring anything done: validate, compile (three targets), replay, coverage, ruff, ip_scan self-test.
- Do not refactor unasked. Do not add dependencies without stating why.
- Push back plainly when a request is wrong, with the reason.
- Prefer the maintainer's phrasing in README and docs. No em-dashes anywhere.

## Definition of done for a rule
Sigma file with the complete metadata contract; compiles to SPL, KQL, and DuckDB SQL; hit and miss samples in tests/samples/<rule_id>/; replay test passes; ATT&CK technique tag present; `do_not_alert_when` written in the maintainer's voice; one dialect idiom noted in the PR description.

## End-of-task report
What changed; gate output verbatim; anything you were unsure about.
