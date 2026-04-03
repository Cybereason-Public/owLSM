from dataclasses import dataclass, field
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from sigma.rule import SigmaRule as PySigmaRule
from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import SigmaString, SigmaNumber, SigmaCompareExpression, SigmaCIDRExpression, SpecialChars
from sigma_rule_loader import (
    SigmaRule, 
    ALL_FIELD_TYPES, 
    FIELD_TO_ENUM,
    STRING_FIELDS,
    IP_FIELDS,
    EVENT_ALLOWED_TARGET_FIELDS,
    detection_has_keywords,
    NUMERIC_MODIFIER_TO_OPERATION,
    ALLOWED_NUMERIC_MODIFIERS,
    ALLOWED_FIELDREF_STRING_MODIFIERS,
    STRING_MODIFIER_TO_COMPARISON,
)
from constants import (
    MAX_NEEDLE_LENGTH,
    MAX_TOTAL_PREDS,
    COMPARISON_TYPE_EXACT_MATCH,
    COMPARISON_TYPE_CONTAINS,
    COMPARISON_TYPE_STARTS_WITH,
    COMPARISON_TYPE_ENDS_WITH,
    COMPARISON_TYPE_EQUAL,
    COMPARISON_TYPE_ABOVE,
    COMPARISON_TYPE_BELOW,
    COMPARISON_TYPE_EQUAL_ABOVE,
    COMPARISON_TYPE_EQUAL_BELOW,
    COMPARISON_TYPE_REGEX,
    AF_INET,
    AF_INET6,
    StringType,
)

@dataclass
class StringEntry:
    value: str
    string_type: StringType = StringType.DEFAULT


@dataclass
class RuleIP:
    ip: str  
    cidr: int  
    ip_type: int  


@dataclass(frozen=True)
class Predicate:
    field: str
    comparison_type: str
    string_idx: int = -1
    numerical_value: int = -1
    fieldref: str = "FIELD_TYPE_NONE"
    
    def __post_init__(self):
        is_string = self.string_idx != -1
        is_numeric = self.numerical_value != -1
        is_fieldref = self.fieldref != "FIELD_TYPE_NONE"
        
        active_count = sum([is_string, is_numeric, is_fieldref])
        if active_count != 1:
            raise ValueError(
                f"Predicate must have exactly one value source set. Got: "
                f"string_idx={self.string_idx}, numerical_value={self.numerical_value}, fieldref={self.fieldref}"
            )
    
    def is_string_predicate(self) -> bool:
        return self.string_idx != -1
    
    def is_numeric_predicate(self) -> bool:
        return self.numerical_value != -1
    
    def is_fieldref_predicate(self) -> bool:
        return self.fieldref != "FIELD_TYPE_NONE"


@dataclass
class ConditionExpr:
    operator_type: str  # "PRED", "AND", "OR", "NOT"
    predicate_idx: Optional[int] = None
    children: Optional[List['ConditionExpr']] = None
    
    def __repr__(self):
        if self.operator_type == "PRED":
            return f"PRED({self.predicate_idx})"
        elif self.operator_type == "NOT":
            return f"NOT({self.children[0]})"
        else:
            child_strs = ", ".join(repr(c) for c in (self.children or []))
            return f"{self.operator_type}([{child_strs}])"


@dataclass
class ParsedRule:
    rule_id: int
    description: str
    action: str
    applied_events: List[str]
    condition_expr: ConditionExpr
    source_file: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None


@dataclass
class ParsedRulesContext:
    id_to_string: Dict[int, StringEntry] = field(default_factory=dict)
    id_to_predicate: Dict[int, Predicate] = field(default_factory=dict)
    id_to_ip: Dict[int, RuleIP] = field(default_factory=dict)
    rules: List[ParsedRule] = field(default_factory=list)
    _string_to_id: Dict[Tuple[str, bool], int] = field(default_factory=dict)
    _pred_to_id: Dict[Predicate, int] = field(default_factory=dict)
    _ip_to_id: Dict[tuple, int] = field(default_factory=dict)
    
    def get_or_add_string(self, s: str, string_type: StringType = StringType.DEFAULT) -> int:
        """
        Add a string to the context or return existing index.
        
        For DEFAULT and CONTAINS strings:
        - They share the same entry (keyed by string value only)
        - If a string is used with CONTAINS, it upgrades from DEFAULT to CONTAINS
        
        For REGEX strings:
        - They have separate entries (different semantics from literal strings)
        """
        is_regex = (string_type == StringType.REGEX)
        key = (s, is_regex)
        
        if key in self._string_to_id:
            idx = self._string_to_id[key]
            if not is_regex and string_type == StringType.CONTAINS:
                if self.id_to_string[idx].string_type == StringType.DEFAULT:
                    self.id_to_string[idx].string_type = StringType.CONTAINS
            return idx
        
        new_idx = len(self.id_to_string)
        self.id_to_string[new_idx] = StringEntry(value=s, string_type=string_type)
        self._string_to_id[key] = new_idx
        return new_idx
    
    def get_or_add_predicate(self, pred: Predicate) -> int:
        if pred in self._pred_to_id:
            return self._pred_to_id[pred]
        
        new_idx = len(self.id_to_predicate)
        if new_idx >= MAX_TOTAL_PREDS:
            raise ValueError(f"Exceeded maximum number of predicates ({MAX_TOTAL_PREDS})")
        self.id_to_predicate[new_idx] = pred
        self._pred_to_id[pred] = new_idx
        return new_idx
    
    def get_or_add_ip(self, rule_ip: RuleIP) -> int:
        key = (rule_ip.ip, rule_ip.cidr, rule_ip.ip_type)
        if key in self._ip_to_id:
            return self._ip_to_id[key]
        
        new_idx = len(self.id_to_ip)
        self.id_to_ip[new_idx] = rule_ip
        self._ip_to_id[key] = new_idx
        return new_idx


def get_string_fields_for_event(event_type: str) -> set:
    common = {f for f in STRING_FIELDS if f.startswith("process.") or f.startswith("parent_process.")}
    target = EVENT_ALLOWED_TARGET_FIELDS.get(event_type, set()) & STRING_FIELDS
    return common | target


class OwlsmBackend(Backend):
    """
    Custom pySigma Backend that builds our predicate tables and expression trees.
    
    Instead of generating query strings, this backend builds:
    - id_to_string table (deduplicated strings)
    - id_to_predicate table (deduplicated predicates)
    - ConditionExpr tree (boolean expression)
    
    Note: pySigma handles modifiers natively. We use:
    - convert_condition_field_compare_op_val for numeric comparisons (gt, gte, lt, lte)
    - cond.modifiers for string modifiers (contains, startswith, endswith)
    """
    
    INTERNAL_WILDCARD = "INTERNAL_WILDCARD"
    name = "owlsm"
    formats = {"default": "Default output format"}
    
    def __init__(self, ctx: ParsedRulesContext, event_type: Optional[str] = None,
                 fieldref_comparisons: Optional[Dict[tuple, str]] = None, **kwargs):
        super().__init__(processing_pipeline=None, **kwargs)
        self.ctx = ctx
        self.event_type = event_type
        self.fieldref_comparisons = fieldref_comparisons or {}
    
    def finalize_query(self, rule, query, index, state, output_format):
        return query
    
    def finalize_output(self, queries):
        return queries
    
    def convert_condition_field_compare_op_val(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> ConditionExpr:
        CompareOperators = SigmaCompareExpression.CompareOperators
        
        op_map = {
            CompareOperators.GT: COMPARISON_TYPE_ABOVE,
            CompareOperators.GTE: COMPARISON_TYPE_EQUAL_ABOVE,
            CompareOperators.LT: COMPARISON_TYPE_BELOW,
            CompareOperators.LTE: COMPARISON_TYPE_EQUAL_BELOW,
        }
        
        field = cond.field
        value: SigmaCompareExpression = cond.value
        operation = op_map.get(value.op, COMPARISON_TYPE_EQUAL)
        numeric_value = int(value.number.to_plain())
        
        pred = Predicate(
            field=field,
            comparison_type=operation,
            numerical_value=numeric_value
        )
        pred_idx = self.ctx.get_or_add_predicate(pred)
        
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> ConditionExpr:
        field = cond.field
        value: SigmaNumber = cond.value
        numeric_value = int(value.number) if hasattr(value, 'number') else int(value)
        pred = Predicate(
            field=field,
            comparison_type=COMPARISON_TYPE_EQUAL,
            numerical_value=numeric_value
        )
        pred_idx = self.ctx.get_or_add_predicate(pred)
        
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
  
    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
        return self.convert_condition_field_eq_val_str(cond, state)

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> ConditionExpr:
        children = [self.convert_condition(arg, state) for arg in cond.args]
        # Flatten nested ANDs
        flattened = []
        for child in children:
            if child.operator_type == "AND" and child.children:
                flattened.extend(child.children)
            else:
                flattened.append(child)
        if len(flattened) == 1:
            return flattened[0]
        return ConditionExpr(operator_type="AND", children=flattened)
    
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> ConditionExpr:
        children = [self.convert_condition(arg, state) for arg in cond.args]
        # Flatten nested ORs
        flattened = []
        for child in children:
            if child.operator_type == "OR" and child.children:
                flattened.extend(child.children)
            else:
                flattened.append(child)
        if len(flattened) == 1:
            return flattened[0]
        return ConditionExpr(operator_type="OR", children=flattened)
    
    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> ConditionExpr:
        child = self.convert_condition(cond.args[0], state)
        return ConditionExpr(operator_type="NOT", children=[child])
    
    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> ConditionExpr:
        """
        Handles enum, IP, and string values.
        First checks if the field is an enum. If it is, it converts the string value to a numeric value.
        Then checks if the field is an IP field. If so, it validates and parses as an IP address.
        Otherwise, it parses the SigmaString to determine the operation type and extracts the string value.
        For internal wildcard patterns (val*ue), creates an AND of startswith and endswith predicates.
        """
        field = cond.field
        sigma_string: SigmaString = cond.value
        
        field_type = ALL_FIELD_TYPES.get(field, "string")
        if field_type == "enum":
            enum_dict = FIELD_TO_ENUM.get(field)
            if enum_dict is None:
                raise Exception(f"No enum mapping defined for field '{field}'")
            string_value = str(sigma_string)
            if string_value in enum_dict:
                numeric_value = enum_dict[string_value]
                pred = Predicate(
                    field=field,
                    comparison_type=COMPARISON_TYPE_EQUAL,
                    numerical_value=numeric_value
                )
                pred_idx = self.ctx.get_or_add_predicate(pred)
                return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
            else:
                raise Exception(f"Unknown enum value '{string_value}' for field '{field}'. Valid values: {list(enum_dict.keys())}")
        
        if field in IP_FIELDS:
            if sigma_string.contains_special():
                raise Exception(f"Wildcards are not allowed in IP address field '{field}'. Got: '{sigma_string}'")
            return self._create_ip_predicate_expr(field, str(sigma_string))
        
        operation, value = self._parse_sigma_string(sigma_string)
        return self._create_field_condition_expr(field, operation, value)
    
    def _create_string_predicate_expr(self, field: str, comparison_type: str, value: str) -> ConditionExpr:
        if comparison_type == COMPARISON_TYPE_CONTAINS:
            string_type = StringType.CONTAINS
        else:
            string_type = StringType.DEFAULT
        string_idx = self.ctx.get_or_add_string(value, string_type=string_type)
        pred = Predicate(field=field, comparison_type=comparison_type, string_idx=string_idx)
        pred_idx = self.ctx.get_or_add_predicate(pred)
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
    
    def _create_ip_predicate_expr(self, field: str, ip_value: str) -> ConditionExpr:
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError as e:
            raise Exception(f"Invalid IP address '{ip_value}' for field '{field}': {e}")
        
        if ip_obj.version == 4:
            ip_type = AF_INET
            ip_str = str(ip_obj)
            cidr = 32
        else:
            ip_type = AF_INET6
            ip_str = ip_obj.exploded
            cidr = 128 
        
        rule_ip = RuleIP(ip=ip_str, cidr=cidr, ip_type=ip_type)
        ip_idx = self.ctx.get_or_add_ip(rule_ip)
        
        pred = Predicate(
            field=field,
            comparison_type=COMPARISON_TYPE_EQUAL,
            numerical_value=ip_idx
        )
        pred_idx = self.ctx.get_or_add_predicate(pred)
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
    
    def _create_field_condition_expr(self, field: str, operation: str, value) -> ConditionExpr:
        if operation == self.INTERNAL_WILDCARD:
            prefix, suffix = value
            prefix_expr = self._create_string_predicate_expr(field, COMPARISON_TYPE_STARTS_WITH, prefix)
            suffix_expr = self._create_string_predicate_expr(field, COMPARISON_TYPE_ENDS_WITH, suffix)
            return ConditionExpr(operator_type="AND", children=[prefix_expr, suffix_expr])
        return self._create_string_predicate_expr(field, operation, value)
    
    def _extract_string_value(self, parts: list, start_idx: int, end_idx: int) -> str:
        string_value = "".join(p for p in parts[start_idx:end_idx] if isinstance(p, str))
        if not string_value:
            raise Exception("Empty string value is not supported.")
        if len(string_value) > MAX_NEEDLE_LENGTH:
            raise Exception(f"String exceeds maximum length: '{string_value}' is {len(string_value)} chars (max {MAX_NEEDLE_LENGTH})")
        
        return string_value

    def _parse_sigma_string(self, sigma_string: SigmaString) -> tuple:
        parts = sigma_string.s
        if not parts:
            raise Exception("Empty string value in rule - this is likely a mistake")
        
        if SpecialChars.WILDCARD_SINGLE in parts:
            raise Exception("Single-character wildcard (?) not supported.")
        
        wildcard_indexes = [i for i, p in enumerate(parts) if p == SpecialChars.WILDCARD_MULTI]
        
        if len(wildcard_indexes) > 2:
            raise Exception("Too many wildcards. Maximum 2 allowed.")
        
        if len(wildcard_indexes) == 2:
            if wildcard_indexes != [0, len(parts) - 1]:
                raise Exception("Two wildcards must be at start and end (*value*).")
            return (COMPARISON_TYPE_CONTAINS, self._extract_string_value(parts, 1, len(parts) - 1))
        
        if len(wildcard_indexes) == 1:
            idx = wildcard_indexes[0]
            if idx == 0:
                return (COMPARISON_TYPE_ENDS_WITH, self._extract_string_value(parts, 1, len(parts)))
            elif idx == len(parts) - 1:
                return (COMPARISON_TYPE_STARTS_WITH, self._extract_string_value(parts, 0, len(parts) - 1))
            else:
                prefix = self._extract_string_value(parts, 0, idx)
                suffix = self._extract_string_value(parts, idx + 1, len(parts))
                return (self.INTERNAL_WILDCARD, (prefix, suffix))
        
        return (COMPARISON_TYPE_EXACT_MATCH, self._extract_string_value(parts, 0, len(parts)))

    def _unsupported(self, name: str):
        raise Exception(f"Unsupported condition type: {name}")
    
    def convert_condition_as_in_expression(self, cond, state):
        self._unsupported("as_in_expression")
    
    def convert_condition_field_eq_field(self, cond, state) -> ConditionExpr:
        field = cond.field
        ref_value = cond.value
        ref_field = ref_value.field

        field_type = ALL_FIELD_TYPES.get(field, "string")

        if (field, ref_field) in self.fieldref_comparisons:
            comparison = self.fieldref_comparisons[(field, ref_field)]
        elif ref_value.starts_with:
            comparison = COMPARISON_TYPE_STARTS_WITH
        elif ref_value.ends_with:
            comparison = COMPARISON_TYPE_ENDS_WITH
        elif field_type == "string":
            comparison = COMPARISON_TYPE_EXACT_MATCH
        else:
            comparison = COMPARISON_TYPE_EQUAL

        fieldref_enum_name = ref_field.upper().replace(".", "_")
        pred = Predicate(
            field=field,
            comparison_type=comparison,
            fieldref=fieldref_enum_name
        )
        pred_idx = self.ctx.get_or_add_predicate(pred)
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
    
    def convert_condition_field_eq_query_expr(self, cond, state):
        self._unsupported("field_eq_query_expr")
    
    def convert_condition_field_eq_val_bool(self, cond, state):
        self._unsupported("field_eq_val_bool")
    
    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> ConditionExpr:
        field = cond.field
        
        if field not in IP_FIELDS:
            raise Exception(f"CIDR modifier can only be used with IP fields. Field '{field}' is not an IP field. Valid IP fields: {sorted(IP_FIELDS)}")
        
        cidr_expr: SigmaCIDRExpression = cond.value
        network = cidr_expr.network
        
        if network.version == 4:
            ip_type = AF_INET
            ip_str = str(network.network_address)
            cidr = network.prefixlen
            if cidr < 0 or cidr > 32:
                raise Exception(f"Invalid CIDR prefix {cidr} for IPv4. Must be 0-32.")
        else:
            ip_type = AF_INET6
            ip_str = network.network_address.exploded
            cidr = network.prefixlen
            if cidr < 0 or cidr > 128:
                raise Exception(f"Invalid CIDR prefix {cidr} for IPv6. Must be 0-128.")
        
        rule_ip = RuleIP(ip=ip_str, cidr=cidr, ip_type=ip_type)
        ip_idx = self.ctx.get_or_add_ip(rule_ip)
        
        pred = Predicate(
            field=field,
            comparison_type=COMPARISON_TYPE_EQUAL,
            numerical_value=ip_idx
        )
        pred_idx = self.ctx.get_or_add_predicate(pred)
        
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
    
    def convert_condition_field_eq_val_null(self, cond, state):
        self._unsupported("field_eq_val_null")
      
    def _create_regex_predicate_expr(self, field: str, pattern: str) -> ConditionExpr:
        """
        Create a regex predicate expression for a given field and pattern.
        Used by both field-specific and keyword regex handlers.
        """
        string_idx = self.ctx.get_or_add_string(pattern, string_type=StringType.REGEX)
        pred = Predicate(field=field, comparison_type=COMPARISON_TYPE_REGEX, string_idx=string_idx)
        pred_idx = self.ctx.get_or_add_predicate(pred)
        return ConditionExpr(operator_type="PRED", predicate_idx=pred_idx)
    
    def convert_condition_field_eq_val_re(self, cond, state) -> ConditionExpr:
        """
        Handle regex value patterns.
        Creates a predicate with COMPARISON_TYPE_REGEX.
        Regex validation is done in sigma_rule_loader.py.
        """
        return self._create_regex_predicate_expr(cond.field, str(cond.value.regexp))
    
    def convert_condition_field_eq_val_timestamp_part(self, cond, state):
        self._unsupported("field_eq_val_timestamp_part")
    
    def convert_condition_field_exists(self, cond, state):
        self._unsupported("field_exists")
    
    def convert_condition_field_not_exists(self, cond, state):
        self._unsupported("field_not_exists")
    
    def convert_condition_query_expr(self, cond, state):
        self._unsupported("query_expr")
    
    def convert_condition_val_num(self, cond, state):
        self._unsupported("val_num")
    
    def convert_condition_val_re(self, cond, state) -> ConditionExpr:
        """
        Handle unbound regex value (keyword regex) by expanding to all string fields for the event type.
        Creates an OR of regex predicates for each string field.
        Regex validation is done in sigma_rule_loader.py.
        """
        if self.event_type is None:
            raise Exception("Regex keywords require event_type to be set in backend")
        
        pattern = str(cond.value.regexp)
        
        fields = get_string_fields_for_event(self.event_type)
        fields = fields - IP_FIELDS
        if not fields:
            raise Exception(f"No string fields found for event type '{self.event_type}'")
        
        predicates = [self._create_regex_predicate_expr(field, pattern) for field in sorted(fields)]
        
        if len(predicates) == 1:
            return predicates[0]
        return ConditionExpr(operator_type="OR", children=predicates)
    
    def convert_condition_val_str(self, cond, state) -> ConditionExpr:
        """
        Handle keyword (unbound string value) by expanding to all string fields for the event type.
        Creates an OR of predicates for each string field.
        """
        if self.event_type is None:
            raise Exception("Keywords require event_type to be set in backend")
        
        keyword: SigmaString = cond.value
        operation, value = self._parse_sigma_string(keyword)
        
        fields = get_string_fields_for_event(self.event_type)
        fields = fields - IP_FIELDS
        if not fields:
            raise Exception(f"No string fields found for event type '{self.event_type}'")
        
        predicates = [self._create_field_condition_expr(field, operation, value) for field in sorted(fields)]
        
        if len(predicates) == 1:
            return predicates[0]
        return ConditionExpr(operator_type="OR", children=predicates)
    
    def convert_correlation_event_count_rule(self, rule, output_format, state):
        self._unsupported("correlation_event_count_rule")
    
    def convert_correlation_temporal_ordered_rule(self, rule, output_format, state):
        self._unsupported("correlation_temporal_ordered_rule")
    
    def convert_correlation_temporal_rule(self, rule, output_format, state):
        self._unsupported("correlation_temporal_rule")
    
    def convert_correlation_value_avg_rule(self, rule, output_format, state):
        self._unsupported("correlation_value_avg_rule")
    
    def convert_correlation_value_count_rule(self, rule, output_format, state):
        self._unsupported("correlation_value_count_rule")
    
    def convert_correlation_value_median_rule(self, rule, output_format, state):
        self._unsupported("correlation_value_median_rule")
    
    def convert_correlation_value_percentile_rule(self, rule, output_format, state):
        self._unsupported("correlation_value_percentile_rule")
    
    def convert_correlation_value_sum_rule(self, rule, output_format, state):
        self._unsupported("correlation_value_sum_rule")
    
    def convert_correlation_extended_temporal_rule(self, rule, output_format, state):
        self._unsupported("correlation_extended_temporal_rule")
    
    def convert_correlation_extended_temporal_ordered_rule(self, rule, output_format, state):
        self._unsupported("correlation_extended_temporal_ordered_rule")
    


def preprocess_neq_modifier(detection: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms |neq fields into separate NOT selections before pySigma sees them.
    
    For each field with |neq in a dict-style selection:
    1. Remove the field from the original selection
    2. Create a new selection with the field (without |neq)
    3. Replace the selection reference in the condition with (sel and not __neq_N)
    
    If a selection has only neq fields, its reference becomes (not __neq_0 and not __neq_1 ...).
    """
    import re as _re

    condition = detection.get("condition", "")
    new_detection = {}
    neq_counter = 0
    sel_replacements = {}

    for sel_name, sel_value in detection.items():
        if sel_name == "condition":
            continue

        if isinstance(sel_value, dict):
            neq_fields = {}
            normal_fields = {}

            for field_key, value in sel_value.items():
                parts = field_key.split("|")
                has_neq = any(p.lower() == "neq" for p in parts[1:])

                if has_neq:
                    clean_parts = [p for p in parts if p.lower() != "neq"]
                    clean_key = "|".join(clean_parts)
                    neq_fields[clean_key] = value
                else:
                    normal_fields[field_key] = value

            if not neq_fields:
                new_detection[sel_name] = sel_value
                continue

            for clean_key, value in neq_fields.items():
                if not isinstance(value, (str, int, float)):
                    raise Exception(
                        f"The |neq modifier only supports a single scalar value "
                        f"(string or number). Got {type(value).__name__} "
                        f"for field '{clean_key}' in selection '{sel_name}'."
                    )

            neq_not_clauses = []
            for clean_key, value in neq_fields.items():
                neq_name = f"__neq_{neq_counter}"
                neq_counter += 1
                new_detection[neq_name] = {clean_key: value}
                neq_not_clauses.append(f"not {neq_name}")

            neq_clause = " and ".join(neq_not_clauses)

            if normal_fields:
                new_detection[sel_name] = normal_fields
                sel_replacements[sel_name] = f"({sel_name} and {neq_clause})"
            else:
                sel_replacements[sel_name] = f"({neq_clause})"

        elif isinstance(sel_value, list):
            for item in sel_value:
                if isinstance(item, dict):
                    for field_key in item.keys():
                        parts = field_key.split("|")
                        if any(p.lower() == "neq" for p in parts[1:]):
                            raise Exception(
                                f"The |neq modifier is not supported in list-style (OR) selections "
                                f"(selection '{sel_name}'). Use a dict-style selection instead."
                            )
            new_detection[sel_name] = sel_value
        else:
            new_detection[sel_name] = sel_value

    if sel_replacements:
        new_condition = condition
        for orig_name in sorted(sel_replacements.keys(), key=len, reverse=True):
            replacement = sel_replacements[orig_name]
            new_condition = _re.sub(
                rf'\b{_re.escape(orig_name)}\b', replacement, new_condition
            )
        new_detection["condition"] = new_condition
    else:
        new_detection["condition"] = condition

    return new_detection




def _preprocess_fieldref_in_dict(sel_dict: dict, fieldref_comparisons: dict) -> dict:
    """Strip numeric and string modifiers from fieldref fields in a single selection dict.
    pySigma's SigmaFieldReference rejects values with wildcards (introduced by startswith/endswith)
    and is incompatible with numeric comparison modifiers, so we strip all such modifiers,
    record the comparison type, and pass only bare |fieldref to pySigma."""
    new_sel = {}
    for field_key, value in sel_dict.items():
        parts = field_key.split("|")
        modifiers_lower = [p.lower() for p in parts[1:]]

        if "fieldref" not in modifiers_lower:
            new_sel[field_key] = value
            continue

        extra = [m for m in modifiers_lower if m not in ("fieldref", "neq")]
        has_numeric = bool(set(extra) & ALLOWED_NUMERIC_MODIFIERS)
        has_string = bool(set(extra) & ALLOWED_FIELDREF_STRING_MODIFIERS)

        if not extra or (not has_numeric and not has_string):
            new_sel[field_key] = value
            continue

        field_name = parts[0]
        mod = extra[0]

        if mod in ALLOWED_NUMERIC_MODIFIERS:
            comparison = NUMERIC_MODIFIER_TO_OPERATION[mod]
        else:
            comparison = STRING_MODIFIER_TO_COMPARISON[mod]

        key = (field_name, value)
        if key in fieldref_comparisons:
            raise Exception(
                f"Duplicate fieldref: field '{field_name}' references '{value}' with multiple "
                f"numeric modifiers or string modifiers in the same selection. Only one comparison per "
                f"(field, target) pair is allowed.")
        fieldref_comparisons[key] = comparison

        stripped_key = field_name + "|fieldref"
        if stripped_key in new_sel:
            raise Exception(
                f"Duplicate fieldref: field '{field_name}' uses 'fieldref' with multiple "
                f"modifiers in the same selection. Only one comparison per "
                f"field is allowed.")
        new_sel[stripped_key] = value

    return new_sel


def preprocess_fieldref_modifier(detection: Dict[str, Any]) -> tuple:
    """Strip numeric modifiers from |fieldref fields before pySigma sees them.
    Returns (new_detection, fieldref_comparisons).
    Must run AFTER preprocess_neq_modifier."""
    fieldref_comparisons: Dict[tuple, str] = {}
    new_detection: Dict[str, Any] = {}

    for sel_name, sel_value in detection.items():
        if sel_name == "condition":
            new_detection[sel_name] = sel_value
            continue

        if isinstance(sel_value, dict):
            new_detection[sel_name] = _preprocess_fieldref_in_dict(sel_value, fieldref_comparisons)
        elif isinstance(sel_value, list):
            new_list = []
            for item in sel_value:
                if isinstance(item, dict):
                    new_list.append(_preprocess_fieldref_in_dict(item, fieldref_comparisons))
                else:
                    new_list.append(item)
            new_detection[sel_name] = new_list
        else:
            new_detection[sel_name] = sel_value

    return new_detection, fieldref_comparisons


def create_pysigma_rule(rule_id: int, description: str, detection: Dict[str, Any]) -> PySigmaRule:
    import uuid
    
    # pySigma requires a valid UUID for the rule ID
    # Generate a deterministic UUID from our rule_id for consistency
    rule_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"owlsm-rule-{rule_id}"))
    rule_dict = {
        "id": rule_uuid,
        "title": description or f"Rule {rule_id}",
        "status": "test",
        "logsource": {
            "category": "owlsm",
            "product": "linux"
        },
        "detection": detection
    }
    
    collection = SigmaCollection.from_dicts([rule_dict])
    return collection.rules[0]


def expand_x_of_conditions(detection: Dict[str, Any]) -> Dict[str, Any]:
    import re
    from itertools import combinations
    
    if "condition" not in detection:
        return detection
    
    condition = detection["condition"]
    selection_names = set(detection.keys()) - {"condition"}
    
    # Validate selection names contain only allowed characters
    valid_name_pattern = re.compile(r'^[\w.\-]+$')
    for name in selection_names:
        if not valid_name_pattern.match(name):
            raise Exception(
                f"Invalid selection name '{name}'. "
                f"Only alphanumeric, underscore, dot, and hyphen characters are allowed."
            )
    
    selection_name_chars = r'[\w.\-]'
    x_of_pattern = re.compile(rf'\b(\d+)\s+of\s+({selection_name_chars}+\*|{selection_name_chars}+)', re.IGNORECASE)
    
    # Collect all matches and their replacements first, then apply from right to left
    # to avoid position shifts when replacing
    replacements = []  # List of (start, end, replacement_string)
    
    for match in x_of_pattern.finditer(condition):
        num_str = match.group(1)
        pattern = match.group(2)
        num_required = int(num_str)
        
        if num_required < 1:
            raise Exception(f"Condition '{match.group(0)}' - quantifier must be at least 1")
        
        # Skip "1 of" - pySigma handles this
        if num_required == 1:
            continue
        
        if pattern.lower() == "them":
            matched_selections = sorted(selection_names)
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            matched_selections = sorted(s for s in selection_names if s.startswith(prefix))
        else:
            matched_selections = [pattern] if pattern in selection_names else []
        
        if not matched_selections:
            continue
        if num_required > len(matched_selections):
            raise Exception(
                f"Condition '{match.group(0)}' requires {num_required} selections, "
                f"but only {len(matched_selections)} match pattern '{pattern}': {matched_selections}")
        
        if num_required == len(matched_selections):
            replacement = "(" + " and ".join(matched_selections) + ")"
        else:
            # Generate all combinations of num_required selections
            combos = list(combinations(matched_selections, num_required))
            
            # Build the expanded condition: (A and B) or (A and C) or (B and C)
            combo_exprs = []
            for combo in combos:
                combo_expr = " and ".join(combo)
                combo_exprs.append(f"({combo_expr})")
            
            replacement = "(" + " or ".join(combo_exprs) + ")"
        
        replacements.append((match.start(), match.end(), replacement))
    
    # Apply replacements from right to left to preserve positions
    result_condition = condition
    for start, end, replacement in reversed(replacements):
        result_condition = result_condition[:start] + replacement + result_condition[end:]
    
    result = dict(detection)
    result["condition"] = result_condition
    return result


def _convert_single_rule(rule: SigmaRule, pysigma_rule: PySigmaRule, ctx: ParsedRulesContext, 
                         applied_events: List[str], event_type: Optional[str] = None,
                         fieldref_comparisons: Optional[Dict[tuple, str]] = None) -> ParsedRule:
    backend = OwlsmBackend(ctx, event_type=event_type, fieldref_comparisons=fieldref_comparisons)
    results = backend.convert_rule(pysigma_rule)
    
    if not results:
        event_info = f" for event {event_type}" if event_type else ""
        raise Exception(f"Failed to parse rule {rule.id}{event_info}: no result from backend")
    
    return ParsedRule(
        rule_id=rule.id,
        description=rule.description,
        action=rule.action,
        applied_events=applied_events,
        condition_expr=results[0],
        source_file=rule.source_file,
        min_version=rule.min_version,
        max_version=rule.max_version
    )


def parse_rule_with_pysigma(rule: SigmaRule, ctx: ParsedRulesContext) -> List[ParsedRule]:
    neq_processed = preprocess_neq_modifier(rule.detection)
    fieldref_processed, fieldref_comparisons = preprocess_fieldref_modifier(neq_processed)
    expanded_detection = expand_x_of_conditions(fieldref_processed)
    pysigma_rule = create_pysigma_rule(rule.id, rule.description, expanded_detection)
    
    if detection_has_keywords(rule.detection):
        return [_convert_single_rule(rule, pysigma_rule, ctx, [event_type], event_type,
                                     fieldref_comparisons) for event_type in rule.events]
    else:
        return [_convert_single_rule(rule, pysigma_rule, ctx, rule.events,
                                     fieldref_comparisons=fieldref_comparisons)]


def parse_rules(rules: List[SigmaRule]) -> ParsedRulesContext:
    ctx = ParsedRulesContext()
    
    for rule in rules:
        parsed_rules = parse_rule_with_pysigma(rule, ctx)
        ctx.rules.extend(parsed_rules)
    
    return ctx