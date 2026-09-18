"""Seeded synthetic telemetry for every rule: one must-hit set and one
must-not-hit set, written as JSONL in the synthetic canonical schema.

Everything here is invented. Addresses come from the RFC 5737 documentation
ranges (192.0.2.0/24 plays the inside network, 198.51.100.0/24 and
203.0.113.0/24 the outside), domains from RFC 2606 (example.com is the
organisation), hosts are HOST-A, HOST-B, HOST-C and the domain controller
HOST-DC1, and the users are alice, bob, carol and dave. The generator is
deterministic for a given seed, so the committed samples can be regenerated
and compared byte for byte.

The miss sets are the interesting half: each carries the near-misses the
rule's filters exist for (the legitimate build path, the domain controller,
the machine account, the admin consent, the internal forward).
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

SEED = 20260918
T0 = datetime(2026, 3, 4, 9, 0, 0)

INSIDE = "192.0.2."
OUTSIDE_A = "198.51.100."
OUTSIDE_B = "203.0.113."
HOSTS = ("HOST-A", "HOST-B", "HOST-C")
DC = "HOST-DC1"
ORG = "example.com"
SYS32 = "C:\\Windows\\System32\\"
VS_MSBUILD = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe"

Rows = list[dict]
Generator = Callable[[random.Random], tuple[Rows, Rows]]
GENERATORS: dict[str, Generator] = {}


def at(minutes: float, hours: float = 0) -> str:
    return (T0 + timedelta(hours=hours, minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generator(rule_id: str) -> Callable[[Generator], Generator]:
    def register(fn: Generator) -> Generator:
        GENERATORS[rule_id] = fn
        return fn

    return register


# ---- row builders: every key of a logsource is always present ----------------


def proc(ts, host, user, image, command_line, parent_image, parent_command_line):
    return {
        "ts": ts,
        "host": host,
        "user": user,
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "parent_command_line": parent_command_line,
        "original_file_name": image.rsplit("\\", 1)[-1],
    }


def netconn(ts, host, user, image, dst_ip, dst_port, initiated="true"):
    return {
        "ts": ts,
        "host": host,
        "user": user,
        "image": image,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "initiated": initiated,
    }


def tgs(ts, src_ip, service_name, target_user_name, encryption="0x17", status="0x0"):
    return {
        "ts": ts,
        "host": DC,
        "event_id": 4769,
        "src_ip": src_ip,
        "service_name": service_name,
        "target_user_name": target_user_name,
        "ticket_encryption_type": encryption,
        "status": status,
    }


def okta(ts, user, event_type, outcome, src_country, src_ip):
    return {
        "ts": ts,
        "user": f"{user}@{ORG}",
        "event_type": event_type,
        "outcome": outcome,
        "src_country": src_country,
        "src_ip": src_ip,
    }


def exchange(ts, user, operation, parameters, src_ip):
    return {
        "ts": ts,
        "user": f"{user}@{ORG}",
        "event_source": "Exchange",
        "operation": operation,
        "parameters": parameters,
        "src_ip": src_ip,
    }


def consent(ts, user, app, permissions, is_admin_consent="False", result="success"):
    return {
        "ts": ts,
        "user": f"{user}@{ORG}",
        "operation": "Consent to application",
        "result": result,
        "is_admin_consent": is_admin_consent,
        "app_display_name": app,
        "permissions": permissions,
    }


def conn(ts, src_ip, dst_ip, dst_port, service, conn_state, duration, orig_bytes, resp_bytes, proto="tcp"):
    return {
        "ts": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "service": service,
        "conn_state": conn_state,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
    }


def smtp(ts, src_ip, mail_from, rcpt_to, subject, user_agent):
    return {
        "ts": ts,
        "src_ip": src_ip,
        "dst_ip": OUTSIDE_A + "25",
        "mail_from": mail_from,
        "rcpt_to": rcpt_to,
        "subject": subject,
        "user_agent": user_agent,
    }


# ---- identity ---------------------------------------------------------------


@generator("mfa_success_multi_country_window")
def _mfa(rng: random.Random) -> tuple[Rows, Rows]:
    mfa, start = "user.authentication.auth_via_mfa", "user.session.start"
    hits = [
        okta(at(5), "alice", mfa, "SUCCESS", "US", OUTSIDE_A + "10"),
        okta(at(10), "bob", mfa, "SUCCESS", "US", OUTSIDE_A + "11"),
        okta(at(22), "alice", start, "SUCCESS", "DE", OUTSIDE_B + "77"),  # second country, same hour
    ]
    misses = [
        okta(at(5), "alice", mfa, "SUCCESS", "US", OUTSIDE_A + "10"),
        okta(at(40, hours=4), "alice", start, "SUCCESS", "DE", OUTSIDE_B + "77"),  # hours apart
        okta(at(30), "bob", mfa, "FAILURE", "DE", OUTSIDE_B + "78"),  # failed attempt does not count
        okta(at(12), "bob", mfa, "SUCCESS", "US", OUTSIDE_A + "11"),
        okta(at(15), "carol", start, "SUCCESS", "US", OUTSIDE_A + "12"),
        okta(at(45), "carol", start, "SUCCESS", "US", OUTSIDE_A + "12"),
    ]
    return hits, misses


@generator("inbox_rule_external_forward")
def _inbox(rng: random.Random) -> tuple[Rows, Rows]:
    hits = [
        exchange(at(3), "bob", "Set-InboxRule", "Name=Newsletters;MoveToFolder=Archive", OUTSIDE_A + "11"),
        exchange(
            at(9),
            "alice",
            "New-InboxRule",
            "Name=Invoices;ForwardTo=smtp:mallory@example.net;DeleteMessage=True",
            OUTSIDE_B + "77",
        ),
    ]
    misses = [
        exchange(at(3), "bob", "Set-InboxRule", "Name=Newsletters;MoveToFolder=Archive", OUTSIDE_A + "11"),
        exchange(at(6), "carol", "New-InboxRule", f"Name=Cover;ForwardTo=dave@{ORG};StopProcessingRules=True", OUTSIDE_A + "12"),
        exchange(at(8), "dave", "Remove-InboxRule", "Identity=Invoices", OUTSIDE_A + "13"),
        exchange(at(11), "alice", "Set-InboxRule", f"Name=Team;RedirectTo=team-lead@{ORG}", OUTSIDE_A + "10"),
    ]
    return hits, misses


@generator("oauth_consent_mail_files_scopes_by_user")
def _consent(rng: random.Random) -> tuple[Rows, Rows]:
    hits = [
        consent(at(2), "carol", "Team Wiki", "User.Read offline_access"),
        consent(at(14), "alice", "Mail Insights Pro", "User.Read Mail.Read offline_access"),
    ]
    misses = [
        consent(at(2), "carol", "Team Wiki", "User.Read offline_access"),  # no mail or files scope
        consent(at(4), "bob", "Example Approved Mail Client", "Mail.ReadWrite offline_access"),  # allowlisted
        consent(at(6), "dave", "Mail Insights Pro", "Mail.Read offline_access", is_admin_consent="True"),
        consent(at(8), "alice", "Mail Insights Pro", "Mail.Read offline_access", result="failure"),
    ]
    return hits, misses


# ---- windows ----------------------------------------------------------------


@generator("msbuild_masquerade_network_egress")
def _msbuild(rng: random.Random) -> tuple[Rows, Rows]:
    rogue = "C:\\ProgramData\\Updates\\msbuild.exe"
    browser = "C:\\Program Files\\Example Browser\\browser.exe"
    hits = [
        netconn(at(1), "HOST-B", "alice", browser, OUTSIDE_A + "5", 443),
        netconn(at(7), "HOST-B", "alice", rogue, OUTSIDE_B + "23", 443),
    ]
    misses = [
        netconn(at(1), "HOST-B", "alice", browser, OUTSIDE_A + "5", 443),
        netconn(at(4), "HOST-C", "carol", VS_MSBUILD, OUTSIDE_A + "40", 443),  # toolchain path
        netconn(at(6), "HOST-B", "alice", rogue, INSIDE + "40", 445),  # internal destination
        netconn(at(9), "HOST-B", "alice", rogue, OUTSIDE_B + "23", 443, initiated="false"),  # inbound
    ]
    return hits, misses


@generator("nltest_domain_trust_enum_workstation")
def _nltest(rng: random.Random) -> tuple[Rows, Rows]:
    cmd, nltest = SYS32 + "cmd.exe", SYS32 + "nltest.exe"
    hits = [
        proc(at(1), "HOST-A", "alice", SYS32 + "notepad.exe", "notepad.exe notes.txt", SYS32 + "explorer.exe", "explorer.exe"),
        proc(at(5), "HOST-A", "alice", nltest, "nltest /domain_trusts /all_trusts", cmd, "cmd.exe"),
    ]
    misses = [
        proc(at(1), "HOST-A", "alice", SYS32 + "notepad.exe", "notepad.exe notes.txt", SYS32 + "explorer.exe", "explorer.exe"),
        proc(at(3), DC, "dave", nltest, "nltest /dclist:example", cmd, "cmd.exe"),  # domain controller
        proc(at(5), "HOST-B", "carol", nltest, "nltest /domain_trusts", SYS32 + "ServerManager.exe", "ServerManager.exe"),
        proc(at(7), "HOST-C", "bob", nltest, "nltest /sc_query:example", cmd, "cmd.exe"),  # not enumeration
    ]
    return hits, misses


@generator("wmi_remote_process_creation")
def _wmi(rng: random.Random) -> tuple[Rows, Rows]:
    wmiprvse, cmd, wmic = SYS32 + "wbem\\WmiPrvSE.exe", SYS32 + "cmd.exe", SYS32 + "wbem\\wmic.exe"
    hits = [
        proc(at(2), "HOST-A", "alice", wmic, 'wmic /node:HOST-B process call create "cmd.exe /c whoami"', cmd, "cmd.exe"),
        proc(at(2.1), "HOST-B", "alice", cmd, "cmd.exe /c whoami", wmiprvse, "WmiPrvSE.exe -secured -Embedding"),
    ]
    misses = [
        proc(at(1), "HOST-B", "svc-endpoint-mgmt", cmd, "cmd.exe /c install.cmd", wmiprvse, "WmiPrvSE.exe -secured -Embedding"),
        proc(at(3), "HOST-C", "bob", SYS32 + "WerFault.exe", "WerFault.exe -u -p 4120", wmiprvse, "WmiPrvSE.exe -secured -Embedding"),
        proc(at(4), "HOST-A", "alice", wmic, "wmic os get caption", cmd, "cmd.exe"),
    ]
    return hits, misses


@generator("kerberos_rc4_tgs_volume_single_host")
def _kerberos(rng: random.Random) -> tuple[Rows, Rows]:
    services = [f"svc-{n}" for n in ("sql", "web", "backup", "print", "monitor", "ci", "vault", "wiki", "erp", "crm", "hr", "mail")]
    attacker = INSIDE + "77"
    hits = [tgs(at(30 + i * 0.5, hours=1), attacker, svc, "bob") for i, svc in enumerate(services)]
    hits += [tgs(at(i * 7), INSIDE + "10", "svc-web", "alice", encryption="0x12") for i in range(4)]
    misses = [tgs(at(30 + i * 0.5, hours=1), INSIDE + "10", f"{h}$", h) for i, h in enumerate(HOSTS * 4)]  # machine accounts
    misses += [tgs(at(i * 12, hours=2), attacker, svc, "bob") for i, svc in enumerate(services)]  # spread over 2h
    misses += [tgs(at(50 + i, hours=4), INSIDE + "11", svc, "carol") for i, svc in enumerate(services[:5])]  # below threshold
    misses += [tgs(at(1), INSIDE + "12", "krbtgt", "dave") for _ in range(12)]
    return hits, misses


# ---- network ----------------------------------------------------------------


@generator("beacon_fixed_destination_high_count")
def _beacon(rng: random.Random) -> tuple[Rows, Rows]:
    def burst(dst_ip, dst_port, n, duration=0.4, hours=0.0):
        rows = []
        for i in range(n):
            jitter = rng.uniform(-3, 3)
            rows.append(
                conn(at(i * 2.5 + jitter / 60, hours=hours), INSIDE + "10", dst_ip, dst_port, None, "SF", duration, rng.randint(300, 900), rng.randint(600, 1500))
            )
        return rows

    hits = burst(OUTSIDE_B + "50", 443, 22)
    hits += [conn(at(20), INSIDE + "10", OUTSIDE_A + "5", 443, "ssl", "SF", 12.0, 48000, 910000)]
    misses = burst(INSIDE + "40", 443, 22)  # internal destination
    misses += burst(OUTSIDE_B + "51", 443, 22, duration=45.0, hours=2)  # long-lived sessions
    misses += burst(OUTSIDE_B + "52", 443, 10, hours=4)  # below threshold
    misses += burst(OUTSIDE_B + "53", 25, 22, hours=6)  # not a web port
    return hits, misses


@generator("reverse_shell_conn_shape")
def _reverse_shell(rng: random.Random) -> tuple[Rows, Rows]:
    victim = INSIDE + "11"
    hits = [
        conn(at(1), victim, OUTSIDE_A + "5", 443, "ssl", "SF", 3.2, 2100, 14000),
        conn(at(4), victim, OUTSIDE_A + "66", 4444, None, "SF", 1800.0, 9200, 3100),
    ]
    misses = [
        conn(at(1), victim, OUTSIDE_A + "5", 443, "ssl", "SF", 3.2, 2100, 14000),
        conn(at(3), victim, OUTSIDE_A + "66", 8443, None, "SF", 1800.0, 9200, 3100),  # known high port
        conn(at(5), victim, OUTSIDE_A + "66", 4444, None, "SF", 30.0, 400, 300),  # short
        conn(at(7), victim, INSIDE + "40", 4444, None, "SF", 1800.0, 9200, 3100),  # internal
        conn(at(9), victim, OUTSIDE_A + "67", 2222, "ssh", "SF", 1800.0, 9200, 3100),  # recognised service
        conn(at(11), victim, OUTSIDE_A + "68", 5000, None, "SF", 1800.0, 9200, 3100, proto="udp"),
    ]
    return hits, misses


# ---- email ------------------------------------------------------------------


@generator("xmailer_cli_mailer_anomaly")
def _xmailer(rng: random.Random) -> tuple[Rows, Rows]:
    hits = [
        smtp(at(1), INSIDE + "12", f"alice@{ORG}", f"bob@{ORG}", "lunch?", "Microsoft Outlook 16.0"),
        smtp(at(6), INSIDE + "12", f"alice@{ORG}", "mallory@example.net", "q3 numbers", "Blat v3.2.24"),
        smtp(at(8), INSIDE + "13", f"bob@{ORG}", "mallory@example.net", "export", "swaks v20240103.0"),
    ]
    misses = [
        smtp(at(1), INSIDE + "12", f"alice@{ORG}", f"bob@{ORG}", "lunch?", "Microsoft Outlook 16.0"),
        smtp(at(2), INSIDE + "20", f"monitoring@{ORG}", f"ops@{ORG}", "nightly report", "Blat v3.2.24"),
        smtp(at(3), INSIDE + "21", f"backup@{ORG}", f"ops@{ORG}", "backup ok", "PowerShell/7.4"),
        smtp(at(5), INSIDE + "13", f"bob@{ORG}", f"carol@{ORG}", "notes", None),
    ]
    return hits, misses


# ---- writer -----------------------------------------------------------------


def generate(seed: int = SEED) -> dict[str, tuple[Rows, Rows]]:
    out: dict[str, tuple[Rows, Rows]] = {}
    for rule_id in sorted(GENERATORS):
        rng = random.Random(f"{seed}:{rule_id}")
        out[rule_id] = GENERATORS[rule_id](rng)
    return out


def write_samples(out_dir: Path, seed: int = SEED) -> dict[str, tuple[int, int]]:
    """Write hit.jsonl and miss.jsonl per rule; return row counts."""
    counts: dict[str, tuple[int, int]] = {}
    for rule_id, (hits, misses) in generate(seed).items():
        d = out_dir / rule_id
        d.mkdir(parents=True, exist_ok=True)
        for name, rows in (("hit.jsonl", hits), ("miss.jsonl", misses)):
            with open(d / name, "w", encoding="utf-8", newline="\n") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
        counts[rule_id] = (len(hits), len(misses))
    return counts
