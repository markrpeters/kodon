"""Two small corrections on top of the pySigma Kusto backend.

* A field name that is not a plain identifier (Sigma's dotted names such as
  id.orig_h) is emitted in KQL bracket form, ['id.orig_h'].
* A CIDR match quotes its field the same way (pySigma formats it raw).
* `in~` is only used for string lists. KQL's in~ compares strings, so a
  numeric list (ports, event ids) is emitted as an OR of == comparisons.
"""

from __future__ import annotations

import copy
import re
from typing import Any, ClassVar

from sigma.backends.kusto import KustoBackend
from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.types import SigmaString

IDENTIFIER: re.Pattern[str] = re.compile(r"^\w+$")


class KodonKustoBackend(KustoBackend):
    name: ClassVar[str] = "Kusto backend (kodon)"

    def escape_and_quote_field(self, field_name: str) -> str:
        if IDENTIFIER.match(field_name) or field_name.startswith("['"):
            return field_name  # plain identifier, or already bracketed by an earlier pass
        return "['" + field_name.replace("'", "\\'") + "']"

    def decide_convert_condition_as_in_expression(self, cond: Any, state: Any) -> bool:
        if not super().decide_convert_condition_as_in_expression(cond, state):
            return False
        return all(
            isinstance(arg, ConditionFieldEqualsValueExpression) and isinstance(arg.value, SigmaString)
            for arg in cond.args
        )

    def convert_condition_field_eq_val_cidr(self, cond: Any, state: Any) -> Any:
        quoted = copy.copy(cond)
        quoted.field = self.escape_and_quote_field(cond.field)
        return super().convert_condition_field_eq_val_cidr(quoted, state)
