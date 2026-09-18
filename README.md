# kodon

[![ci](https://github.com/markrpeters/kodon/actions/workflows/ci.yml/badge.svg)](https://github.com/markrpeters/kodon/actions/workflows/ci.yml)

Detections should be files in a repo, not rules in a console: version-controlled,
reviewed, tested against data that must trigger them and data that must not,
validated in CI, mapped to ATT&CK with the gaps listed, and deployed from the
pipeline rather than by hand. kodon is that lifecycle. Rules are written in
Sigma (vendor-neutral), compiled to Splunk SPL, Microsoft Sentinel KQL and
DuckDB SQL with pySigma, and replay-tested against synthetic telemetry in
DuckDB. pySigma does the compiling; what kodon adds is the contract around
each rule (required metadata, generated must-hit and must-not-hit samples,
replay, a declared ATT&CK scope) and the CI that enforces it.

Ten rules ship today, each built around a pattern the author has had to
detect in practice. Each carries a must-hit and a must-not-hit
sample set, an ATT&CK mapping, and a `do_not_alert_when` block that says when
the rule should run as a hunt query rather than page as an alert. Status: 0.0.1, alpha, a personal project.
Requires Python 3.10 or newer; the test suite runs offline in about a second.

## 30-second demo

```bash
git clone https://github.com/markrpeters/kodon && cd kodon
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
kodon demo
```

The demo generates the seeded samples into a temporary directory, validates
every rule against the metadata contract, compiles all of them to the three
targets, replays the DuckDB SQL over the samples, and prints the coverage
matrix. A rule looks like this (excerpt of
`rules/windows/nltest_domain_trust_enum_workstation.yml`):

```yaml
detection:
  selection:
    Image|endswith: '\nltest.exe'
    CommandLine|contains:
      - 'domain_trusts'
      - 'all_trusts'
      - 'trusted_domains'
      - 'dclist'
      - 'dsgetdc'
  filter_domain_controllers:
    ComputerName|startswith: 'HOST-DC'
  filter_admin_tooling:
    ParentImage|endswith:
      - '\ServerManager.exe'
      - '\dsac.exe'
  condition: selection and not 1 of filter_*
custom:
  do_not_alert_when: |
    The parent is a known management tool or the user is in the directory
    administrators group and the host is their assigned admin workstation;
    filter by parent process, not by user name alone, because attackers run as
    the compromised admin. Treat /dsgetdc on its own as a hunt (scripts use
    it); /domain_trusts and /all_trusts from a standard user should alert.
```

And the demo output, with one correlation rule shown in all three languages:

```text
[1/5] generated seeded samples for 10 rules (57 must-hit rows, 152 must-miss rows)
[2/5] validated 10 rules against the metadata contract
[3/5] compiled 10 rules to splunk, kql, duckdb

example, mfa_success_multi_country_window:
--- splunk
eventType IN ("user.authentication.auth_via_mfa", "user.session.start") outcome.result="SUCCESS"
| bin _time span=1h
| stats dc(client.geographicalContext.country) as value_count by _time actor.alternateId
| search value_count >= 2
--- kql
Okta_CL
| where (eventType in~ ("user.authentication.auth_via_mfa", "user.session.start")) and ['outcome.result'] =~ "SUCCESS"
| summarize value_count = dcount(['client.geographicalContext.country']) by bin(TimeGenerated, 1h), ['actor.alternateId']
| where value_count >= 2
--- duckdb
SELECT time_bucket(INTERVAL '3600 seconds', ts) AS bucket, user, COUNT(DISTINCT src_country) AS value_count
FROM (SELECT * FROM events
      WHERE (event_type ILIKE 'user.authentication.auth\_via\_mfa' ESCAPE '\'
             OR event_type ILIKE 'user.session.start' ESCAPE '\')
        AND outcome ILIKE 'SUCCESS' ESCAPE '\') AS subquery
GROUP BY 1, user HAVING COUNT(DISTINCT src_country) >= 2

[4/5] replay: compiled DuckDB SQL over the samples
      (a rule passes when it matches at least one hit row and zero miss rows)
rule_id                                    hit rows  matched miss rows  matched  result
xmailer_cli_mailer_anomaly                        3        2         4        0  PASS
inbox_rule_external_forward                       2        1         4        0  PASS
mfa_success_multi_country_window                  3        1         6        0  PASS
...
kerberos_rc4_tgs_volume_single_host              16        1        41        0  PASS

[5/5] coverage
ATT&CK coverage: 12/24 in-scope techniques have at least one rule; 12 gaps
```

The Splunk and KQL output is compiled, not deployed: field names stay Sigma's
until you pass your own field-mapping pipeline (see *How to compile*), and only
the DuckDB target is replay-tested.

## The rules

| rule | logsource | technique | kind |
|---|---|---|---|
| `identity/mfa_success_multi_country_window` | okta | T1078.004, T1621 | correlation |
| `identity/inbox_rule_external_forward` | m365 exchange | T1114.003 | event |
| `identity/oauth_consent_mail_files_scopes_by_user` | azure auditlogs | T1528 | event |
| `windows/msbuild_masquerade_network_egress` | windows network_connection | T1127.001, T1036.005 | event |
| `windows/nltest_domain_trust_enum_workstation` | windows process_creation | T1482 | event |
| `windows/wmi_remote_process_creation` | windows process_creation | T1047 | event |
| `windows/kerberos_rc4_tgs_volume_single_host` | windows security | T1558.003 | correlation |
| `network/beacon_fixed_destination_high_count` | zeek conn | T1071.001 | correlation |
| `network/reverse_shell_conn_shape` | zeek conn | T1571 | event |
| `email/xmailer_cli_mailer_anomaly` | zeek smtp | T1048.003 | event |

The patterns are well known and several have SigmaHQ cousins; the selections,
filters, samples and `do_not_alert_when` text here are written from scratch,
and each rule cites the ATT&CK page for its technique.

## How to add a rule

1. Write `rules/<domain>/<rule_id>.yml` in Sigma. The file stem is the rule id.
   The Sigma `id` is derived, not invented: `uuid5(NAMESPACE_URL, "kodon:<rule_id>")`
   written as 32 hex characters (see *Design notes* for why no hyphens).
   The loader refuses any other value.
2. Fill the metadata contract. Besides the Sigma fields the loader requires
   `status`, `level`, `date`, at least one `attack.tNNNN` tag and one
   `attack.<tactic>` tag, a non-empty `falsepositives` list, and a `custom`
   block:

   ```yaml
   custom:
     data_sources: [what log this needs, precisely]
     do_not_alert_when: |
       The judgment call: the conditions under which this stays a hunt.
     detection_health: {added: 2026-09-18, last_reviewed: 2026-09-18, owner: Mark Peters}
   ```

   `do_not_alert_when` is mandatory and is the most important field in the
   file. A rule that cannot say when it should not fire is not finished.
3. For a threshold rule, append a Sigma correlation document to the same file
   (`event_count` or `value_count`, with `group-by` and `timespan`). Give the
   base rule a `name` and reference it. Three of the shipped rules show this.
4. Add a generator to `src/kodon/synth.py` under `@generator("<rule_id>")`
   that returns the must-hit rows and the must-not-hit rows, then run
   `python scripts/gen_samples.py` to write `tests/samples/<rule_id>/`.
   Samples are never written by hand; a test regenerates them from the seed
   and compares byte for byte with the committed files. Put the near-misses in
   the miss set: the legitimate path, the domain controller, the machine
   account, the admin consent. Those rows are what the filters are for.
5. If the technique is new, add it to `coverage/attack_scope.yml`.
6. `pytest`. A rule without both sample sets, or with a miss that matches,
   does not merge.

## How to compile

```bash
kodon compile --target splunk
kodon compile --target kql --rule wmi_remote_process_creation
kodon compile --target duckdb
```

Field names in the Splunk and KQL output are the Sigma taxonomy names
(`Image`, `CommandLine`, `id.orig_h`). Mapping them onto a deployment's real
columns is a pySigma processing pipeline the deployment owns; pass it as
`pipeline=` to `kodon.compile_rule`. `pipelines/synthetic_canonical.yml` is
the public example of that file: it maps the same names onto the synthetic
schema the tests run against. A deployment ships its own copy for its own
schema and nothing else changes. `pipelines/kql_tables.yml` picks the Sentinel
table per logsource.

## How to test

```bash
pytest          # validate, compile, replay, coverage; offline
kodon test      # the replay table only
kodon validate  # the metadata contract only
```

Replay is the gate: each rule's DuckDB SQL runs over
`tests/samples/<rule_id>/hit.jsonl` and must match at least one row, then over
`miss.jsonl` and must match none. It is a regression test against synthetic
rows, not proof against production telemetry; that proof comes from the
deployment's own data once the rule is compiled for it. Hits come back as
`DetectionHit` records (rule id, technique, severity, the matched row or the
matched aggregate), the same contract a downstream consumer receives from
`kodon.replay`.

## Coverage report

```bash
kodon coverage            # text matrix, gaps marked
kodon coverage --json     # the CoverageReport contract
```

Gaps are computed against the declared scope in `coverage/attack_scope.yml`,
not against all of ATT&CK. The scope is a choice, so the percentage is too; a
matrix that is red everywhere says nothing, and a scope says what the rule
set was meant to cover. The gaps are the work list. CI uploads the report as
an artifact on every push.

## Design notes

**Sigma ids without hyphens.** The data-hygiene scanner that gates every
commit and CI run (`scripts/ip_scan.sh`) flags hyphenated UUIDs, and exempting
the rules directory would leave the files most likely to carry a copied
identifier unscanned. Python's `uuid.UUID` and pySigma both accept the 32-hex
form, and ids are derived from the rule id so they are reproducible.

**Correlation windows are fixed buckets.** All three targets aggregate into
fixed time buckets (`bin _time span=`, `bin(TimeGenerated, …)`,
`time_bucket(INTERVAL …)`). A burst that straddles a bucket boundary can be
missed; a sliding window is a roadmap item, not something to hide.

**KQL correlations are kodon's.** pySigma's Kusto backend (1.0) does not emit
correlation rules, so kodon appends the `summarize` clause itself, using the
same fields and window the other two targets use. kodon's DuckDB backend is a
thin subclass of the maintained pySigma SQLite backend: `ILIKE` because Sigma
matching is case-insensitive and DuckDB's `LIKE` is not, `regexp_matches()`
because DuckDB has no `REGEXP`, and the time bucketing above. Underscores in
values are escaped (`auth\_via\_mfa`) because `_` is a `LIKE` wildcard.

**Synthetic address plan.** Samples use the RFC 5737 documentation ranges:
192.0.2.0/24 plays the inside network, 198.51.100.0/24 and 203.0.113.0/24 the
outside. Domains are RFC 2606 (`example.com` is the organisation). Hosts are
HOST-A, HOST-B, HOST-C and the domain controller HOST-DC1. Where a rule needs
an "internal" range or a naming prefix, it uses these, with a comment that a
deployment substitutes its own.

**One-way dependency.** kodon is also a library, used by a separate private
project of the author's that passes its own field-mapping pipeline and
consumes the `DetectionHit` records. Nothing private is referenced, imported
or tested here; the scanner and its self-test run in CI and as a pre-commit
hook to keep it that way.

## Roadmap

- Sliding-window correlations, and interval-variance scoring for the beacon
  rule (periodicity, not just count).
- More rules, generalised from hunt queries in the downstream project.
- Optional Defender XDR and Sentinel ASIM field mapping for the Windows
  categories via the pipelines that ship with pysigma-backend-kusto.
- Deployment: push compiled output to a SIEM from CI. Compile is the
  deliverable today; deployment is deliberately not.

## How this is built

Agentic coding tools (Claude Code) are used in this repository under an
eval-gated methodology: nothing merges without the test suite, the replay
gate, the data-hygiene scan and its self-test, a cold-read review of
user-facing text, and a recorded decision log for anything that departs from
the work order.

## Why the name

A codon is the smallest unit of genetic code that encodes one instruction. A
rule here is one encoded instruction: a Sigma file with its samples and
metadata, compiled into whichever language the target speaks. The k is a
spelling swap to stay clear of the Codon compiler.

## License

Apache-2.0. Copyright 2026 Mark Peters ([github.com/markrpeters](https://github.com/markrpeters)).
