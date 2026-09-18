"""compile(rule, target) -> query string.

Targets:
  splunk  pySigma Splunk backend, no field mapping (Sigma taxonomy field names)
  kql     pySigma Kusto backend + pipelines/kql_tables.yml (table per logsource)
  duckdb  kodon's DuckDB backend + pipelines/synthetic_canonical.yml

Field names in the splunk and kql output are the Sigma taxonomy names. Mapping
them onto a deployment's actual columns is a processing pipeline the deployment
owns and passes in as `pipeline=`; that is the seam a downstream consumer fills.
"""

from __future__ import annotations

import copy
from functools import cache

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from kodon.duckdb_backend import DuckDBBackend
from kodon.kusto_backend import KodonKustoBackend
from kodon.loader import LoadedRule, resource_dir

TARGETS = ("splunk", "kql", "duckdb")
DEFAULT_PIPELINE_FILE = {"kql": "kql_tables.yml", "duckdb": "synthetic_canonical.yml"}
KQL_TIMESTAMP = "TimeGenerated"
KQL_UNITS = {"s": "s", "m": "m", "h": "h", "d": "d"}
KQL_OPS = {"LT": "<", "LTE": "<=", "GT": ">", "GTE": ">=", "EQ": "==", "NEQ": "!="}


@cache
def _pipeline_from_file(path: str) -> ProcessingPipeline:
    with open(path, encoding="utf-8") as fh:
        return ProcessingPipeline.from_yaml(fh.read())


def default_pipeline(target: str) -> ProcessingPipeline | None:
    name = DEFAULT_PIPELINE_FILE.get(target)
    if name is None:
        return None
    return _pipeline_from_file(str(resource_dir("pipelines") / name))


def _backend(target: str, pipeline: ProcessingPipeline | None) -> Backend:
    if target == "splunk":
        return SplunkBackend(pipeline)
    if target == "kql":
        return KodonKustoBackend(pipeline)
    if target == "duckdb":
        return DuckDBBackend(pipeline)
    raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")


def _fresh(loaded: LoadedRule) -> tuple[SigmaCollection, SigmaRule, SigmaCorrelationRule | None]:
    """pySigma pipelines rewrite field names on the rule object itself, so
    each compilation works on its own deep copy of the parsed collection."""
    collection = copy.deepcopy(loaded.collection)
    rule = next(r for r in collection.rules if isinstance(r, SigmaRule))
    corr = next((r for r in collection.rules if isinstance(r, SigmaCorrelationRule)), None)
    return collection, rule, corr


def _kql(backend: KodonKustoBackend, rule: SigmaRule, corr: SigmaCorrelationRule | None) -> str:
    """The Kusto backend does not emit correlation rules (pysigma-backend-kusto
    1.0), so kodon appends the summarize clause itself: the same fixed-window
    aggregation the Splunk and DuckDB outputs use."""
    rule._output = True  # a rule referenced by a correlation is marked non-output
    body = backend.convert_rule(rule)[0]
    pipeline = backend.last_processing_pipeline
    table = pipeline.state.get("query_table")
    query = f"{table}\n| where {body}" if table else f"search {body}"
    if corr is None:
        return query
    pipeline.apply(corr)  # maps the group-by and value-count fields like the rule's own
    span = corr.timespan
    kql_span = f"{span.count * 7}d" if span.unit == "w" else f"{span.count}{KQL_UNITS[span.unit]}"
    fields = ", ".join(backend.escape_and_quote_field(f) for f in corr.group_by or [])
    if corr.type.name.lower() == "event_count":
        agg, alias = "event_count = count()", "event_count"
    else:
        field = backend.escape_and_quote_field(str(corr.condition.fieldref))
        agg, alias = f"value_count = dcount({field})", "value_count"
    op = KQL_OPS[corr.condition.op.name]
    return (
        f"{query}\n| summarize {agg} by bin({KQL_TIMESTAMP}, {kql_span}), {fields}"
        f"\n| where {alias} {op} {corr.condition.count}"
    )


def compile_rule(
    loaded: LoadedRule, target: str, pipeline: ProcessingPipeline | None = None
) -> str:
    """Compile one loaded rule (its correlation, if it has one) for a target."""
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")
    pipeline = pipeline if pipeline is not None else default_pipeline(target)
    backend = _backend(target, pipeline)
    collection, rule, corr = _fresh(loaded)
    if target == "kql":
        return _kql(backend, rule, corr)  # type: ignore[arg-type]
    queries = backend.convert(collection)
    if len(queries) != 1:
        raise RuntimeError(f"{loaded.rule_id}: expected one query for {target}, got {len(queries)}")
    return queries[0]


def compile_all(
    rules: list[LoadedRule], target: str, pipeline: ProcessingPipeline | None = None
) -> dict[str, str]:
    return {lr.rule_id: compile_rule(lr, target, pipeline) for lr in rules}
