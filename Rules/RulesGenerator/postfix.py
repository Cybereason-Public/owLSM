from dataclasses import dataclass
import sys
from typing import List, Optional
from AST import ConditionExpr, ParsedRule, ParsedRulesContext
from constants import MAX_TOKENS_PER_RULE, OperatorType


def log_info(message):
    print(message, file=sys.stderr)


@dataclass
class Token:
    """A single token in the postfix expression."""
    operator_type: OperatorType
    predicate_idx: Optional[int] = None
    
    def __repr__(self):
        if self.operator_type == OperatorType.OPERATOR_PREDICATE:
            return f"PRED({self.predicate_idx})"
        else:
            return self.operator_type.name.replace("OPERATOR_", "")
    
    def __eq__(self, other):
        if not isinstance(other, Token):
            return False
        return self.operator_type == other.operator_type and self.predicate_idx == other.predicate_idx


@dataclass
class PostfixRule:
    rule_id: int
    description: str
    title: str
    severity: str
    mitre_tags: List[str]
    name: str
    author: str
    action: str
    applied_events: List[str]
    tokens: List[Token]
    source_file: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None


@dataclass
class PostfixRulesContext:
    id_to_string: dict
    id_to_predicate: dict
    id_to_ip: dict
    rules: List[PostfixRule]


def condition_expr_to_postfix(expr: ConditionExpr) -> List[Token]:
    tokens: List[Token] = []
    
    if expr.operator_type == "PRED":
        tokens.append(Token(operator_type=OperatorType.OPERATOR_PREDICATE, predicate_idx=expr.predicate_idx))
    
    elif expr.operator_type == "AND":
        if not expr.children:
            raise Exception("AND node has no children")
        
        for child in expr.children:
            tokens.extend(condition_expr_to_postfix(child))
        
        for _ in range(len(expr.children) - 1):
            tokens.append(Token(operator_type=OperatorType.OPERATOR_AND))
    
    elif expr.operator_type == "OR":
        if not expr.children:
            raise Exception("OR node has no children")
        
        for child in expr.children:
            tokens.extend(condition_expr_to_postfix(child))
        
        for _ in range(len(expr.children) - 1):
            tokens.append(Token(operator_type=OperatorType.OPERATOR_OR))
    
    elif expr.operator_type == "NOT":
        if not expr.children or len(expr.children) != 1:
            raise Exception("NOT node must have exactly one child")
        
        tokens.extend(condition_expr_to_postfix(expr.children[0]))
        tokens.append(Token(operator_type=OperatorType.OPERATOR_NOT))
    
    else:
        raise Exception(f"Unknown expression type: {expr.operator_type}")
    
    return tokens


def convert_rule_to_postfix(parsed_rule: ParsedRule) -> PostfixRule:
    tokens = condition_expr_to_postfix(parsed_rule.condition_expr)
    
    if len(tokens) > MAX_TOKENS_PER_RULE:
        raise Exception(f"Rule {parsed_rule.rule_id} exceeds maximum token limit: {len(tokens)} tokens (max {MAX_TOKENS_PER_RULE}). Simplify the rule condition.")
    
    return PostfixRule(
        rule_id=parsed_rule.rule_id,
        description=parsed_rule.description,
        title=parsed_rule.title,
        severity=parsed_rule.severity,
        mitre_tags=parsed_rule.mitre_tags,
        name=parsed_rule.name,
        author=parsed_rule.author,
        action=parsed_rule.action,
        applied_events=parsed_rule.applied_events,
        tokens=tokens,
        source_file=parsed_rule.source_file,
        min_version=parsed_rule.min_version,
        max_version=parsed_rule.max_version
    )


def convert_to_postfix(ctx: ParsedRulesContext) -> PostfixRulesContext:
    postfix_rules = []
    for parsed_rule in ctx.rules:
        postfix_rule = convert_rule_to_postfix(parsed_rule)
        postfix_rules.append(postfix_rule)
    
    return PostfixRulesContext(
        id_to_string=ctx.id_to_string,
        id_to_predicate=ctx.id_to_predicate,
        id_to_ip=ctx.id_to_ip,
        rules=postfix_rules
    )


def print_postfix_context(ctx: PostfixRulesContext) -> None:
    """Print the postfix context for debugging."""
    log_info("id_to_string:")
    for idx, entry in sorted(ctx.id_to_string.items()):
        contains_tag = " [CONTAINS]" if entry.is_contains else ""
        log_info(f"  {idx}: {repr(entry.value)}{contains_tag}")
    
    log_info("id_to_predicate:")
    for idx, pred in sorted(ctx.id_to_predicate.items()):
        log_info(
            f"  {idx}: Predicate({pred.field}, {pred.comparison_type}, string_idx={pred.string_idx})",
        )
    
    log_info("")
    log_info("Postfix Rules:")
    for rule in ctx.rules:
        log_info(f"\nRule {rule.rule_id}: {rule.description}")
        log_info(f"  Action: {rule.action}")
        log_info(f"  Tokens ({len(rule.tokens)}): {' '.join(repr(t) for t in rule.tokens)}")

