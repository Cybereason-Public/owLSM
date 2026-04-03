import json
from typing import Any, Dict
from pathlib import Path
from postfix import PostfixRulesContext, PostfixRule, Token, OperatorType
from AST import Predicate, RuleIP

def serialize_predicate(pred: Predicate) -> Dict[str, Any]:
    return {
        "field": pred.field,
        "comparison_type": pred.comparison_type,
        "string_idx": pred.string_idx,
        "numerical_value": pred.numerical_value,
        "fieldref": pred.fieldref
    }

def serialize_ip(rule_ip: RuleIP) -> Dict[str, Any]:
    return {
        "ip": rule_ip.ip,
        "cidr": rule_ip.cidr,
        "ip_type": rule_ip.ip_type
    }

def serialize_token(token: Token) -> Dict[str, Any]:
    result = {"operator_type": token.operator_type.value}  
    if token.operator_type == OperatorType.OPERATOR_PREDICATE:
        result["predicate_idx"] = token.predicate_idx
    
    return result


def serialize_rule(rule: PostfixRule) -> Dict[str, Any]:
    result = {
        "id": rule.rule_id,
        "description": rule.description,
        "action": rule.action,
        "applied_events": rule.applied_events,
        "tokens": [serialize_token(t) for t in rule.tokens]
    }
    
    if rule.min_version is not None:
        result["min_version"] = rule.min_version
    
    if rule.max_version is not None:
        result["max_version"] = rule.max_version
    
    return result


def serialize_context(ctx: PostfixRulesContext) -> Dict[str, Any]:
    id_to_string_json = {
        str(idx): {"value": entry.value, "string_type": entry.string_type.value}
        for idx, entry in ctx.id_to_string.items()
    }

    id_to_predicate_json = {
        str(idx): serialize_predicate(pred) 
        for idx, pred in ctx.id_to_predicate.items()
    }
    
    id_to_ip_json = {
        str(idx): serialize_ip(rule_ip)
        for idx, rule_ip in ctx.id_to_ip.items()
    }
    
    rules_json = [serialize_rule(rule) for rule in ctx.rules]
    
    return {
        "id_to_string": id_to_string_json,
        "id_to_predicate": id_to_predicate_json,
        "id_to_ip": id_to_ip_json,
        "rules": rules_json
    }


def to_json_string(ctx: PostfixRulesContext, indent: int = 2) -> str:
    data = serialize_context(ctx)
    return json.dumps(data, indent=indent)


def write_json_file(ctx: PostfixRulesContext, output_path: str, indent: int = 2) -> None:
    json_str = to_json_string(ctx, indent)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(json_str)

