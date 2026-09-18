"""A thin DuckDB backend built on the maintained pySigma SQLite backend.

Three things differ from SQLite and matter for correctness:

* Sigma string matching is case-insensitive. SQLite's LIKE is; DuckDB's is
  not, so every string match is emitted as ILIKE.
* DuckDB has no REGEXP operator; regular expressions use regexp_matches().
* The SQLite backend ignores a correlation's timespan. Here event_count and
  value_count are bucketed with time_bucket() over the timestamp column, the
  same fixed-window approximation Splunk's `bin _time span=` uses.
"""

from __future__ import annotations

from typing import Any, ClassVar

from sigma.backends.sqlite import sqliteBackend
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationTypeLiteral
from sigma.exceptions import SigmaConversionError

DEFAULT_TABLE = "events"
DEFAULT_TIMESTAMP = "ts"


class DuckDBBackend(sqliteBackend):
    name: ClassVar[str] = "DuckDB backend (kodon)"
    formats: ClassVar[dict[str, str]] = {"default": "DuckDB SQL"}

    eq_expression: ClassVar[str] = "{field} ILIKE {value} ESCAPE '\\'"
    startswith_expression: ClassVar[str] = "{field} ILIKE '{value}%' ESCAPE '\\'"
    endswith_expression: ClassVar[str] = "{field} ILIKE '%{value}' ESCAPE '\\'"
    contains_expression: ClassVar[str] = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = "{field} ILIKE '{value}' ESCAPE '\\'"
    wildcard_match_str_expression: ClassVar[str] = "{field} ILIKE '{value}' ESCAPE '\\'"
    re_expression: ClassVar[str] = "regexp_matches({field}, '{regex}')"
    field_quote: ClassVar[str] = '"'
    table = DEFAULT_TABLE
    timestamp_field = DEFAULT_TIMESTAMP

    def convert_condition_field_eq_val_str(self, cond: Any, state: Any) -> Any:
        # SQLite's backend falls through to `field = value` for plain strings,
        # which is case-sensitive in DuckDB. Route plain equality through ILIKE.
        value = cond.value
        if not value.contains_special():
            return self.eq_expression.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
            )
        return super().convert_condition_field_eq_val_str(cond, state)

    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> list[str]:
        if correlation_type not in ("event_count", "value_count"):
            raise SigmaConversionError(
                rule, rule.source, f"correlation type {correlation_type!r} not supported by kodon"
            )
        state = self.last_processing_pipeline.state
        table = state.get("table", self.table)
        ts = state.get("timestamp_field", self.timestamp_field)
        search = self.convert_correlation_search(rule).replace("FROM logs", f"FROM {table}")
        group_fields = [self.escape_and_quote_field(f) for f in rule.group_by or []]
        seconds = self.convert_timespan(rule.timespan, method)
        bucket = f"time_bucket(INTERVAL '{seconds} seconds', {self.escape_and_quote_field(ts)}) AS bucket"
        if correlation_type == "event_count":
            aggregate = "COUNT(*)"
            alias = "event_count"
        else:
            aggregate = f"COUNT(DISTINCT {self.escape_and_quote_field(str(rule.condition.fieldref))})"
            alias = "value_count"
        op = self.correlation_condition_mapping[rule.condition.op]
        select = ", ".join([bucket, *group_fields, f"{aggregate} AS {alias}"])
        group = ", ".join(["1", *group_fields])
        return [
            f"SELECT {select} FROM ({search}) AS subquery "
            f"GROUP BY {group} HAVING {aggregate} {op} {rule.condition.count}"
        ]
