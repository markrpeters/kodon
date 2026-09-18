"""Run compiled DuckDB SQL over telemetry and return hits.

Sources accepted by `replay`: a DuckDB connection that already has the events
table, a path to a JSONL or Parquet file, or an in-memory list of dicts.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
from sigma.processing.pipeline import ProcessingPipeline

from kodon.compile import compile_rule
from kodon.contracts import DetectionHit
from kodon.duckdb_backend import DEFAULT_TABLE
from kodon.loader import LoadedRule

Source = duckdb.DuckDBPyConnection | Path | str | list[dict[str, Any]]


def load_events(source: Source, table: str = DEFAULT_TABLE) -> duckdb.DuckDBPyConnection:
    """Materialise the source as `table` in a DuckDB connection."""
    if isinstance(source, duckdb.DuckDBPyConnection):
        return source
    con = duckdb.connect()
    if isinstance(source, list):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8")
        with tmp:
            for row in source:
                tmp.write(json.dumps(row, default=str) + "\n")
        path = Path(tmp.name)
    else:
        path = Path(source)
    if path.suffix == ".parquet":
        con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_parquet(?)", [str(path)])
    else:
        con.execute(
            f"CREATE TABLE {table} AS SELECT * FROM read_json(?, format='newline_delimited', "
            "auto_detect=true, sample_size=-1)",
            [str(path)],
        )
    # A column that is null in every row is typed JSON; make it a string so
    # comparisons behave like the other rows' columns would.
    for name, typ, *_ in con.execute(f"DESCRIBE {table}").fetchall():
        if typ == "JSON":
            con.execute(f'ALTER TABLE {table} ALTER "{name}" TYPE VARCHAR')
    return con


def run_sql(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict[str, Any]]:
    cur = con.execute(sql)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]


def replay(
    rules: list[LoadedRule],
    source: Source,
    pipeline: ProcessingPipeline | None = None,
) -> list[DetectionHit]:
    """Compile every rule to DuckDB SQL, run it over the source, return hits."""
    con = load_events(source)
    hits: list[DetectionHit] = []
    for lr in rules:
        sql = compile_rule(lr, "duckdb", pipeline)
        for row in run_sql(con, sql):
            hits.append(
                DetectionHit(
                    rule_id=lr.meta.rule_id,
                    sigma_id=lr.meta.sigma_id,
                    title=lr.meta.title,
                    level=lr.meta.level,
                    kind=lr.meta.kind,
                    techniques=lr.meta.techniques,
                    tactics=lr.meta.tactics,
                    matched=row,
                )
            )
    return hits


@dataclass
class ReplayResult:
    rule_id: str
    hit_rows: int
    hit_matches: int
    miss_rows: int
    miss_matches: int

    @property
    def passed(self) -> bool:
        return self.hit_matches > 0 and self.miss_matches == 0


def replay_samples(loaded: LoadedRule, samples_dir: Path) -> ReplayResult:
    """The test a rule must pass: hit.jsonl produces at least one hit,
    miss.jsonl produces none."""
    d = samples_dir / loaded.rule_id
    hit_path, miss_path = d / "hit.jsonl", d / "miss.jsonl"
    if not hit_path.is_file() or not miss_path.is_file():
        raise FileNotFoundError(f"{loaded.rule_id}: samples missing under {d}")
    sql = compile_rule(loaded, "duckdb")
    hit_con, miss_con = load_events(hit_path), load_events(miss_path)
    return ReplayResult(
        rule_id=loaded.rule_id,
        hit_rows=hit_con.execute(f"SELECT count(*) FROM {DEFAULT_TABLE}").fetchone()[0],
        hit_matches=len(run_sql(hit_con, sql)),
        miss_rows=miss_con.execute(f"SELECT count(*) FROM {DEFAULT_TABLE}").fetchone()[0],
        miss_matches=len(run_sql(miss_con, sql)),
    )
