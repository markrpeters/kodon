"""Every rule compiles to SPL, KQL and DuckDB SQL without error, and the
compiled text carries the idioms we expect from each target."""

from __future__ import annotations

import pytest

from kodon.compile import TARGETS, compile_all, compile_rule


@pytest.mark.parametrize("target", TARGETS)
def test_compiles(loaded, target: str) -> None:
    q = compile_rule(loaded, target)
    assert q.strip()


def test_splunk_idioms(loaded) -> None:
    q = compile_rule(loaded, "splunk")
    if loaded.correlation is not None:
        assert "| bin _time span=" in q and "| stats" in q
    assert "ILIKE" not in q and "| where" not in q


def test_kql_idioms(loaded) -> None:
    q = compile_rule(loaded, "kql")
    table, _, body = q.partition("\n")
    assert table and " " not in table, "first line is the table name"
    assert body.startswith("| where ")
    assert "=~" in q or "endswith" in q or "contains" in q
    assert "in~ (" not in q or all(ch not in q for ch in ("in~ (8", "in~ (4"))
    if loaded.correlation is not None:
        assert "| summarize" in q and "bin(TimeGenerated," in q
    # dotted Sigma names must be bracket-quoted, never bare or single-quoted
    for token in q.replace("(", " ").replace(")", " ").split():
        if "." in token and not token.startswith(("['", '"', "'")) and token[0].isalpha():
            assert not token.endswith("_h") and "." not in token.split("=")[0], token


def test_duckdb_idioms(loaded) -> None:
    q = compile_rule(loaded, "duckdb")
    assert q.startswith("SELECT ")
    assert "FROM events" in q
    assert " LIKE " not in q, "Sigma string matches are case-insensitive: ILIKE only"
    assert " REGEXP " not in q
    if loaded.correlation is not None:
        assert "time_bucket(INTERVAL" in q and "HAVING COUNT(" in q


def test_compile_is_pure(loaded) -> None:
    before = compile_rule(loaded, "duckdb")
    compile_rule(loaded, "kql")
    compile_rule(loaded, "splunk")
    assert compile_rule(loaded, "duckdb") == before


def test_compile_all_covers_every_rule(rules) -> None:
    for target in TARGETS:
        out = compile_all(rules, target)
        assert set(out) == {lr.rule_id for lr in rules}


def test_unknown_target(rules) -> None:
    with pytest.raises(ValueError):
        compile_rule(rules[0], "sqlite")
