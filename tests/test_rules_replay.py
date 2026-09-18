"""Load samples into DuckDB, run the compiled SQL, assert hit and miss. Also
pin the samples to the seeded generator so nothing hand-written creeps in."""

from __future__ import annotations

import json
from pathlib import Path

from kodon.contracts import DetectionHit
from kodon.replay import replay, replay_samples
from kodon.synth import GENERATORS, SEED, write_samples

SAMPLES = Path(__file__).resolve().parent / "samples"


def test_must_hit_and_must_miss(loaded) -> None:
    r = replay_samples(loaded, SAMPLES)
    assert r.hit_matches > 0, f"{loaded.rule_id}: hit.jsonl produced no match"
    assert r.miss_matches == 0, f"{loaded.rule_id}: miss.jsonl produced {r.miss_matches} matches"
    assert r.passed


def test_replay_api_returns_contract_hits(loaded) -> None:
    hits = replay([loaded], SAMPLES / loaded.rule_id / "hit.jsonl")
    assert hits and all(isinstance(h, DetectionHit) for h in hits)
    h = hits[0]
    assert h.rule_id == loaded.rule_id and h.sigma_id == loaded.meta.sigma_id
    assert h.techniques == loaded.meta.techniques and h.kind == loaded.meta.kind
    if loaded.correlation is not None:
        assert "bucket" in h.matched and ("event_count" in h.matched or "value_count" in h.matched)
    else:
        assert "ts" in h.matched
    assert json.loads(h.model_dump_json())["rule_id"] == loaded.rule_id


def test_replay_accepts_rows(loaded) -> None:
    rows = [json.loads(line) for line in (SAMPLES / loaded.rule_id / "hit.jsonl").read_text().splitlines()]
    assert replay([loaded], rows)


def test_every_rule_has_a_generator(rules) -> None:
    assert {lr.rule_id for lr in rules} == set(GENERATORS)


def test_committed_samples_match_generator(tmp_path: Path, rules) -> None:
    write_samples(tmp_path, SEED)
    for lr in rules:
        for name in ("hit.jsonl", "miss.jsonl"):
            fresh = (tmp_path / lr.rule_id / name).read_bytes()
            committed = (SAMPLES / lr.rule_id / name).read_bytes()
            assert fresh == committed, f"{lr.rule_id}/{name} differs from the generator; run scripts/gen_samples.py"


def test_samples_use_documentation_ranges_only(rules) -> None:
    import re

    ip = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    for lr in rules:
        for name in ("hit.jsonl", "miss.jsonl"):
            for m in ip.finditer((SAMPLES / lr.rule_id / name).read_text()):
                prefix = ".".join(m.groups()[:3])
                assert prefix in {"192.0.2", "198.51.100", "203.0.113"}, f"{lr.rule_id}: {m.group()}"
