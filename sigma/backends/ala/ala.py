from sigma.collection import SigmaCollection
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionNOT
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from typing import Any, ClassVar, Dict, List, Optional, Union


class AzureLogAnalyticsBackend(TextQueryBackend):
    """Azure Log Analytics Queries backend."""
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = " == "

    str_quote : ClassVar[str] = "'"
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "?"

    re_expression : ClassVar[str] = "{field} matches regex '(?i){regex}'"
    re_escape_char : ClassVar[str] = "\\"

    cidr_expression : ClassVar[str] = 'ipv4_is_in_range({field}, "{value}")'
    cidr_in_list_expression : ClassVar[str] = "{field} in ({list})"

    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field}!=*"

    field_in_list_expression : ClassVar[str] = "{field} in ({list})"
    list_separator : ClassVar[str] = ", "

    unbound_value_str_expression : ClassVar[str] = "* contains '{value}'"
    unbound_value_num_expression : ClassVar[str] = "* contains '{value}'"
    unbound_value_re_expression : ClassVar[str] = '"{value}"'

    deferred_start : ClassVar[str] = "\n"
    deferred_separator : ClassVar[str] = "\n"

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, min_time : str = "-30d", max_time : str = "now", **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.min_time = min_time or "-30d"
        self.max_time = max_time or "now"
    
    def choose_table_name(self, rule : SigmaRule) -> str:
        if not self.processing_pipeline: # if not any processing pipeline -> return product category
            return rule.logsource.category or rule.logsource.product
        elif self.processing_pipeline:
            product = rule.logsource.product
            category = rule.logsource.category

            for item in self.processing_pipeline.items:
                if item.rule_conditions:
                    if item.rule_conditions[0].product == product and item.rule_conditions[0].service == category:
                        return item.transformation.val
        return rule.logsource.product
    
    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                return self.not_token + self.token_separator + "(" + self.convert_condition_group(arg, state) + ")"
            else:
                expr = self.convert_condition(arg, state)
                # expr = None
                if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                    return expr.negate()
                else:                                             # convert negated expression to string
                    return self.not_token + self.token_separator + "(" + expr + ")"
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def finalize_query(self, rule : SigmaRule, query : Any, index : int, state : ConversionState, output_format : str):
        return super().finalize_query(
            rule,
            f"{self.choose_table_name(rule=rule)} | where ({query})",
            index,
            state,
            output_format
        )

    def finalize_output_default(self, queries : List[Any]) -> Any:
        if len(queries) == 1:
            return queries[0]
        return queries

