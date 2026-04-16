import os
import re
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
import yaml
from placeholder_expander import expand_detection_placeholders
from constants import (
    FILE_TYPE_ENUM,
    CONNECTION_DIRECTION_ENUM,
    RULE_FIELD_TYPES,
    ALLOWED_ACTIONS,
    VALID_EVENT_TYPES,
    MAX_RULES_PER_MAP,
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
)
from regex_dfa import validate_regex_or_raise
from field_mapping import apply_field_mapping_to_detection

# Derive field sets from the single source of truth (constants.json)
ALL_FIELD_TYPES: Dict[str, str] = RULE_FIELD_TYPES

def _filter_fields(prefix: str) -> Dict[str, str]:
    return {k: v for k, v in ALL_FIELD_TYPES.items() if k.startswith(prefix)}

PROCESS_FIELDS = _filter_fields("process.")
TARGET_FILE_FIELDS = _filter_fields("target.file.")
TARGET_PROCESS_FIELDS = _filter_fields("target.process.")
CHMOD_SPECIFIC_FIELDS = _filter_fields("chmod.")
RENAME_SPECIFIC_FIELDS = _filter_fields("rename.")
NETWORK_SPECIFIC_FIELDS = _filter_fields("network.")

ALLOWED_FIELDS: Set[str] = {f for f, t in ALL_FIELD_TYPES.items() if t != "none"}
STRING_FIELDS: Set[str] = {f for f, t in ALL_FIELD_TYPES.items() if t == "string"}
NUMERIC_FIELDS: Set[str] = {f for f, t in ALL_FIELD_TYPES.items() if t == "numeric"}
ENUM_FIELDS: Set[str] = {f for f, t in ALL_FIELD_TYPES.items() if t == "enum"}
IP_FIELDS: Set[str] = {"network.source_ip", "network.destination_ip"}

FIELD_TO_ENUM = {
    "process.file.type": FILE_TYPE_ENUM,
    "parent_process.file.type": FILE_TYPE_ENUM,
    "target.file.type": FILE_TYPE_ENUM,
    "target.process.file.type": FILE_TYPE_ENUM,
    "rename.source_file.type": FILE_TYPE_ENUM,
    "rename.destination_file.type": FILE_TYPE_ENUM,
    "network.direction": CONNECTION_DIRECTION_ENUM,
}

FILE_TARGET_EVENTS = {"CHMOD", "CHOWN", "READ", "WRITE", "UNLINK", "FILE_CREATE", "MKDIR", "RMDIR"}
PROCESS_TARGET_EVENTS = {"EXEC"}
RENAME_EVENTS = {"RENAME"}
NETWORK_EVENTS = {"NETWORK"}

EVENT_ALLOWED_TARGET_FIELDS: Dict[str, Set[str]] = {
    "CHMOD": set(TARGET_FILE_FIELDS.keys()) | set(CHMOD_SPECIFIC_FIELDS.keys()),
    "CHOWN": set(TARGET_FILE_FIELDS.keys()),
    "READ": set(TARGET_FILE_FIELDS.keys()),
    "WRITE": set(TARGET_FILE_FIELDS.keys()),
    "UNLINK": set(TARGET_FILE_FIELDS.keys()),
    "FILE_CREATE": set(TARGET_FILE_FIELDS.keys()),
    "MKDIR": set(TARGET_FILE_FIELDS.keys()),
    "RMDIR": set(TARGET_FILE_FIELDS.keys()),
    "EXEC": set(TARGET_PROCESS_FIELDS.keys()),
    "RENAME": set(RENAME_SPECIFIC_FIELDS.keys()),
    "NETWORK": set(NETWORK_SPECIFIC_FIELDS.keys()),
}

ALL_TARGET_FIELDS: Set[str] = (
    set(TARGET_FILE_FIELDS.keys()) |
    set(TARGET_PROCESS_FIELDS.keys()) |
    set(CHMOD_SPECIFIC_FIELDS.keys()) |
    set(RENAME_SPECIFIC_FIELDS.keys()) |
    set(NETWORK_SPECIFIC_FIELDS.keys())
)

ALLOWED_STRING_MODIFIERS: Set[str] = {"contains", "startswith", "endswith", "re"}
ALLOWED_NUMERIC_MODIFIERS: Set[str] = {"gt", "gte", "lt", "lte"}
ALLOWED_IP_MODIFIERS: Set[str] = {"cidr"} 
ALLOWED_MODIFIERS: Set[str] = ALLOWED_STRING_MODIFIERS | ALLOWED_NUMERIC_MODIFIERS | ALLOWED_IP_MODIFIERS

REQUIRED_FIELDS: Set[str] = {"id", "description", "action", "events", "detection"}

VERSION_PATTERN = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')


def validate_version_field(version: Any, field_name: str, rule_file: str) -> str:
    if not isinstance(version, str):
        raise Exception(
            f"Validation error in '{rule_file}': Field '{field_name}' must be a string, "
            f"got {type(version).__name__}"
        )
    
    if not VERSION_PATTERN.match(version):
        raise Exception(
            f"Validation error in '{rule_file}': Field '{field_name}' has invalid format '{version}'. "
            f"Expected format: MAJOR.MINOR.PATCH (e.g., '1.0.0'). Leading zeros are not allowed."
        )
    
    return version
@dataclass
class FieldModifiers:
    field_name: str
    field_type: str
    comparison: str
    is_fieldref: bool = False
    
    
@dataclass
class SigmaRule:
    id: int
    description: str
    action: str
    events: List[str]
    detection: Dict[str, Any]
    source_file: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None


NUMERIC_MODIFIER_TO_OPERATION = {
    "gt": COMPARISON_TYPE_ABOVE,
    "gte": COMPARISON_TYPE_EQUAL_ABOVE,
    "lt": COMPARISON_TYPE_BELOW,
    "lte": COMPARISON_TYPE_EQUAL_BELOW,
}


ALLOWED_FIELDREF_STRING_MODIFIERS: Set[str] = {"startswith", "endswith"}

STRING_MODIFIER_TO_COMPARISON = {
    "startswith": COMPARISON_TYPE_STARTS_WITH,
    "endswith": COMPARISON_TYPE_ENDS_WITH,
}


def parse_field_key(field_key: str) -> FieldModifiers:
    parts = field_key.split("|")
    field_name = parts[0]
    
    if field_name not in ALLOWED_FIELDS:
        raise Exception(f"Invalid field '{field_name}'. Allowed fields: {sorted(ALLOWED_FIELDS)}")

    field_type = ALL_FIELD_TYPES[field_name]
    is_ip_field = field_name in IP_FIELDS
    
    if field_type == "string":
        comparison = COMPARISON_TYPE_EXACT_MATCH
    else: 
        comparison = COMPARISON_TYPE_EQUAL
    
    has_quantifier = False
    has_modifier = False
    has_fieldref = False
    
    for modifier in parts[1:]:
        modifier_lower = modifier.lower()
        
        if modifier_lower == "fieldref":
            if has_fieldref:
                raise Exception(f"Duplicate 'fieldref' modifier in field key '{field_key}'.")
            if is_ip_field:
                raise Exception(
                    f"The 'fieldref' modifier cannot be used with IP fields. "
                    f"Field '{field_name}' is an IP field.")
            has_fieldref = True
            continue
        
        elif modifier_lower == "all":
            if has_fieldref:
                raise Exception(
                    f"The 'all' modifier cannot be combined with 'fieldref' in field key '{field_key}'.")
            if has_quantifier:
                raise Exception(f"Multiple quantifiers in field key '{field_key}'. Only one 'all' quantifier is allowed.")
            has_quantifier = True
            continue
        
        elif modifier_lower == "neq":
            if has_modifier or has_quantifier:
                raise Exception(f"The 'neq' modifier cannot be combined with other modifiers or quantifiers in field key '{field_key}'.")
            has_modifier = True
            has_quantifier = True
        
        elif modifier_lower == "cidr":
            if has_fieldref:
                raise Exception(
                    f"The 'cidr' modifier cannot be combined with 'fieldref' in field key '{field_key}'.")
            if not is_ip_field:
                raise Exception(f"Modifier 'cidr' can only be used with IP fields. Field '{field_name}' is not an IP field. Valid IP fields: {sorted(IP_FIELDS)}")
            if has_modifier:
                raise Exception(f"Multiple modifiers in field key '{field_key}'. Only one modifier is allowed.")
            has_modifier = True
        
        elif field_type == "string":
            if modifier_lower in ALLOWED_STRING_MODIFIERS:
                if has_modifier:
                    raise Exception(f"Multiple modifiers in field key '{field_key}'. Only one modifier is allowed.")
                if has_fieldref and modifier_lower not in ALLOWED_FIELDREF_STRING_MODIFIERS:
                    raise Exception(
                        f"The '{modifier_lower}' modifier cannot be combined with 'fieldref' in field key '{field_key}'.")
                has_modifier = True
                if modifier_lower == "contains":
                    comparison = COMPARISON_TYPE_CONTAINS
                elif modifier_lower == "startswith":
                    comparison = COMPARISON_TYPE_STARTS_WITH
                elif modifier_lower == "endswith":
                    comparison = COMPARISON_TYPE_ENDS_WITH
                elif modifier_lower == "re":
                    if has_fieldref:
                        raise Exception(
                            f"The 're' modifier cannot be combined with 'fieldref' in field key '{field_key}'.")
                    comparison = COMPARISON_TYPE_REGEX
            else:
                allowed = ALLOWED_STRING_MODIFIERS | ALLOWED_IP_MODIFIERS if is_ip_field else ALLOWED_STRING_MODIFIERS
                raise Exception(f"Invalid modifier '{modifier}' for string field '{field_name}'. Allowed modifiers: {allowed}")
        
        elif field_type in ("numeric", "enum"):
            if has_fieldref and field_type == "enum":
                raise Exception(
                    f"Enum fields with 'fieldref' do not support additional modifiers besides 'neq'. "
                    f"Field: '{field_key}'.")
            if modifier_lower in ALLOWED_NUMERIC_MODIFIERS:
                if has_modifier:
                    raise Exception(f"Multiple modifiers in field key '{field_key}'. Only one modifier is allowed.")
                has_modifier = True
                comparison = NUMERIC_MODIFIER_TO_OPERATION[modifier_lower]
            else:
                raise Exception(f"Invalid modifier '{modifier}' for {field_type} field '{field_name}'. Allowed numeric modifiers: {ALLOWED_NUMERIC_MODIFIERS}")
        
        else:
            raise Exception(f"Invalid modifier '{modifier}'. Allowed modifiers: {ALLOWED_MODIFIERS}")
    
    return FieldModifiers(field_name, field_type, comparison, has_fieldref)


def get_unescaped_wildcard_positions(value: str) -> list:
    positions = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == '\\' and i + 1 < len(value):
            i += 2
            continue
        if char in ('*', '?'):
            positions.append((i, char))
        i += 1
    return positions


def validate_wildcard_pattern(value: str, field_key: str, selection_name: str, rule_file: str) -> None:
    wildcard_positions = get_unescaped_wildcard_positions(value)
    if not wildcard_positions:
        return 
    
    if any(char == '?' for _, char in wildcard_positions):
        raise Exception(f"unescaped single character wildcard (?) is not supported. file: {rule_file}")
    
    wildcard_count = len(wildcard_positions)
    
    if wildcard_count > 2:
        raise Exception(f"field '{field_key}': too many wildcards ({wildcard_count}). Maximum 2 wildcards allowed. file: {rule_file}")
    
    if value == '*':
        raise Exception(f"field '{field_key}': a single '*' is not a valid pattern. file: {rule_file}")
    
    if wildcard_count == 2:
        pos1 = wildcard_positions[0][0]
        pos2 = wildcard_positions[1][0]
        if pos1 != 0 or pos2 != len(value) - 1:
            raise Exception(f"When using 2 wildcards, they must be at the start and end (*value*). file: {rule_file}")


def is_keyword_selection(selection_value: Any) -> bool:
    # Format 1: Direct list of strings
    if isinstance(selection_value, list):
        if len(selection_value) == 0:
            return False
        return all(isinstance(item, str) for item in selection_value)
    
    # Format 2: Dict with only '|all' key
    if isinstance(selection_value, dict):
        if len(selection_value) == 1 and '|all' in selection_value:
            inner = selection_value['|all']
            if isinstance(inner, list) and len(inner) > 0:
                return all(isinstance(item, str) for item in inner)
    
    return False


def detection_has_keywords(detection: Dict[str, Any]) -> bool:
    for selection_name, selection_value in detection.items():
        if selection_name == "condition":
            continue
        if is_keyword_selection(selection_value):
            return True
    return False


def validate_keyword_list(keywords: list, selection_name: str, rule_file: str) -> None:
    if len(keywords) == 0:
        raise Exception(f"Validation error in '{rule_file}': Keyword selection '{selection_name}': empty list is not allowed")
    
    seen_values = set()
    for idx, keyword in enumerate(keywords):
        if not isinstance(keyword, str):
            raise Exception(
                f"Validation error in '{rule_file}': Keyword selection '{selection_name}' item {idx}: "
                f"expected string, got {type(keyword).__name__}"
            )
        
        if keyword == "":
            raise Exception(f"Validation error in '{rule_file}': Keyword selection '{selection_name}' item {idx}: empty string is not allowed")
        
        if keyword in seen_values:
            raise Exception(f"Validation error in '{rule_file}': Keyword selection '{selection_name}': duplicate keyword '{keyword}'")

        seen_values.add(keyword)
        
        validate_wildcard_pattern(keyword, f"keyword[{idx}]", selection_name, rule_file)


def validate_keyword_selection(selection_name: str, selection_value: Any, rule_file: str) -> None:
    if isinstance(selection_value, list):
        validate_keyword_list(selection_value, selection_name, rule_file)
    elif isinstance(selection_value, dict) and '|all' in selection_value:
        validate_keyword_list(selection_value['|all'], selection_name, rule_file)
    else:
        raise Exception(f"Validation error in '{rule_file}': Invalid keyword selection format")


def _field_key_has_neq(field_key: str) -> bool:
    parts = field_key.split("|")
    return any(p.lower() == "neq" for p in parts[1:])


def validate_selection_item(item: Dict[str, Any], selection_name: str, rule_file: str) -> None:

    for field_key, values in item.items():
        try:
            field_info = parse_field_key(field_key)
        except Exception as e:
            raise Exception(f"Validation error in '{rule_file}': In selection '{selection_name}': {e}")
        
        if _field_key_has_neq(field_key) and not isinstance(values, (str, int, float)):
            raise Exception(
                f"Validation error in '{rule_file}': In selection '{selection_name}', "
                f"field '{field_key}': the 'neq' modifier only supports a single scalar value "
                f"(string or number). Got {type(values).__name__}."
            )
        
        if field_info.is_fieldref:
            if not isinstance(values, str):
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"field '{field_key}': the 'fieldref' modifier requires a single field name string. "
                    f"Got {type(values).__name__}.")
            if values not in ALLOWED_FIELDS:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"field '{field_key}': fieldref target '{values}' is not a valid field. "
                    f"Allowed fields: {sorted(ALLOWED_FIELDS)}")
            if values in IP_FIELDS:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"field '{field_key}': fieldref cannot reference IP fields. "
                    f"'{values}' is an IP field.")
            target_type = ALL_FIELD_TYPES[values]
            if target_type != field_info.field_type:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"field '{field_key}': fieldref type mismatch. "
                    f"Field '{field_info.field_name}' is '{field_info.field_type}' "
                    f"but target '{values}' is '{target_type}'.")
            continue
        
        field_type = field_info.field_type
        
        if field_type == "string":
            if field_info.comparison == COMPARISON_TYPE_REGEX:
                if isinstance(values, str):
                    try:
                        validate_regex_or_raise(values, f"field '{field_key}'")
                    except Exception as e:
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"{e}"
                        )
                elif isinstance(values, list):
                    for idx, v in enumerate(values):
                        if not isinstance(v, str):
                            raise Exception(
                                f"Validation error in '{rule_file}': In selection '{selection_name}', "
                                f"regex field '{field_key}': values must be strings, got {type(v).__name__}"
                            )
                        try:
                            validate_regex_or_raise(v, f"field '{field_key}' value {idx}")
                        except Exception as e:
                            raise Exception(
                                f"Validation error in '{rule_file}': In selection '{selection_name}', "
                                f"{e}"
                            )
                else:
                    raise Exception(
                        f"Validation error in '{rule_file}': In selection '{selection_name}', "
                        f"regex field '{field_key}': value must be string or list of strings, got {type(values).__name__}"
                    )
            elif isinstance(values, str):
                validate_wildcard_pattern(values, field_key, selection_name, rule_file)
            elif isinstance(values, list):
                for v in values:
                    if not isinstance(v, str):
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"string field '{field_key}': values must be strings, got {type(v).__name__}"
                        )
                    validate_wildcard_pattern(v, field_key, selection_name, rule_file)
            else:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"string field '{field_key}': value must be string or list of strings, got {type(values).__name__}"
                )
        
        elif field_type == "numeric":
            if isinstance(values, int) and not isinstance(values, bool):
                if values < 0:
                    raise Exception(
                        f"Validation error in '{rule_file}': In selection '{selection_name}', "
                        f"numeric field '{field_key}': negative values are not allowed, got {values}"
                    )
            elif isinstance(values, list):
                for v in values:
                    if not isinstance(v, int) or isinstance(v, bool):
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"numeric field '{field_key}': values must be integers, got {type(v).__name__}"
                        )
                    if v < 0:
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"numeric field '{field_key}': negative values are not allowed, got {v}"
                        )
            else:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"numeric field '{field_key}': value must be integer or list of integers, got {type(values).__name__}"
                )
        
        elif field_type == "enum":
            enum_dict = FIELD_TO_ENUM.get(field_info.field_name)
            if enum_dict is None:
                raise Exception(f"No enum mapping defined for field '{field_info.field_name}'")
            valid_enums = set(enum_dict.keys())
            
            if isinstance(values, str):
                if values not in valid_enums:
                    raise Exception(
                        f"Validation error in '{rule_file}': In selection '{selection_name}', "
                        f"enum field '{field_key}': invalid enum value '{values}'. "
                        f"Valid values: {sorted(valid_enums)}"
                    )
            elif isinstance(values, list):
                for v in values:
                    if not isinstance(v, str):
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"enum field '{field_key}': values must be strings, got {type(v).__name__}"
                        )
                    if v not in valid_enums:
                        raise Exception(
                            f"Validation error in '{rule_file}': In selection '{selection_name}', "
                            f"enum field '{field_key}': invalid enum value '{v}'. "
                            f"Valid values: {sorted(valid_enums)}"
                        )
            else:
                raise Exception(
                    f"Validation error in '{rule_file}': In selection '{selection_name}', "
                    f"enum field '{field_key}': value must be string or list of strings, got {type(values).__name__}"
                )


def validate_selection(selection_name: str, selection_value: Any, rule_file: str) -> None:
    if selection_name == "condition":
        return
    
    if is_keyword_selection(selection_value):
        validate_keyword_selection(selection_name, selection_value, rule_file)
        return
    
    if isinstance(selection_value, dict):
        validate_selection_item(selection_value, selection_name, rule_file)
    elif isinstance(selection_value, list):
        if len(selection_value) == 0:
            raise Exception(
                f"Validation error in '{rule_file}': Selection '{selection_name}': "
                f"empty list is not allowed"
            )
        for idx, item in enumerate(selection_value):
            if not isinstance(item, dict):
                raise Exception(
                    f"Validation error in '{rule_file}': Selection '{selection_name}' item {idx}: "
                    f"expected dict, got {type(item).__name__}"
                )
            validate_selection_item(item, selection_name, rule_file)
    else:
        raise Exception(
            f"Validation error in '{rule_file}': Selection '{selection_name}': "
            f"expected dict or list, got {type(selection_value).__name__}"
        )


def validate_detection(detection: Dict[str, Any], rule_file: str) -> None:
    if "condition" not in detection:
        raise Exception(
            f"Validation error in '{rule_file}': Detection must have a 'condition' field"
        )
    
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise Exception(f"Validation error in '{rule_file}': Condition must be a string, got {type(condition).__name__}")
    
    selection_names = set(detection.keys()) - {"condition"}
    if not selection_names:
        raise Exception(f"Validation error in '{rule_file}': Detection must have at least one selection")
    
    for selection_name in selection_names:
        validate_selection(selection_name, detection[selection_name], rule_file)


def validate_events(events: Any, rule_file: str) -> List[str]:
    if not isinstance(events, list):
        raise Exception(f"Validation error in '{rule_file}': Field 'events' must be a list, got {type(events).__name__}")
    
    if len(events) == 0:
        raise Exception(f"Validation error in '{rule_file}': Field 'events' must contain at least one event type")
    
    validated_events: List[str] = []
    seen_events: Set[str] = set()
    
    for event in events:
        if not isinstance(event, str):
            raise Exception(f"Validation error in '{rule_file}': Event type must be a string, got {type(event).__name__}")
        
        event_upper = event.upper()
        if event_upper not in VALID_EVENT_TYPES:
            raise Exception(f"Validation error in '{rule_file}': Invalid event type '{event}'. Valid event types: {sorted(VALID_EVENT_TYPES)}")
        
        if event_upper in seen_events:
            raise Exception(f"Validation error in '{rule_file}': Duplicate event type '{event}'")
        
        seen_events.add(event_upper)
        validated_events.append(event_upper)
    
    return validated_events


def extract_fields_from_detection(detection: Dict[str, Any]) -> Set[str]:
    fields: Set[str] = set()
    
    for selection_name, selection_value in detection.items():
        if selection_name == "condition":
            continue
        
        if isinstance(selection_value, dict):
            for field_key in selection_value.keys():
                # Extract field name (before any modifiers)
                field_name = field_key.split("|")[0]
                fields.add(field_name)
        elif isinstance(selection_value, list):
            for item in selection_value:
                if isinstance(item, dict):
                    for field_key in item.keys():
                        field_name = field_key.split("|")[0]
                        fields.add(field_name)
    
    return fields


def get_allowed_target_fields_for_events(events: List[str]) -> Set[str]:
    if not events:
        return set()

    allowed = EVENT_ALLOWED_TARGET_FIELDS.get(events[0], set()).copy()
    for event in events[1:]:
        event_allowed = EVENT_ALLOWED_TARGET_FIELDS.get(event, set())
        allowed = allowed & event_allowed
    
    return allowed


def validate_fields_for_events(detection: Dict[str, Any], events: List[str], rule_file: str) -> None:
    used_fields = extract_fields_from_detection(detection)
    used_target_fields: Set[str] = set()
    for field in used_fields:
        if field.startswith("process.") or field.startswith("parent_process."):
            continue # Always allowed
        elif field in ALL_TARGET_FIELDS:
            used_target_fields.add(field)
    
    if not used_target_fields:
        return
    
    allowed_target_fields = get_allowed_target_fields_for_events(events)
    disallowed = used_target_fields - allowed_target_fields
    if disallowed:
        if len(events) > 1:
            raise Exception(
                f"Validation error in '{rule_file}': "
                f"Target fields {sorted(disallowed)} are not compatible with events {events}. "
                f"When multiple events are specified, only fields valid for ALL events can be used. "
                f"Allowed target fields for these events: {sorted(allowed_target_fields) if allowed_target_fields else 'none (use only process/parent_process fields)'}"
            )
        else:
            event = events[0]
            raise Exception(
                f"Validation error in '{rule_file}': "
                f"Target fields {sorted(disallowed)} are not valid for event '{event}'. "
                f"Allowed target fields for {event}: {sorted(allowed_target_fields)}"
            )
    

def validate_rule(rule_data: Dict[str, Any], rule_file: str) -> SigmaRule:
    for field in REQUIRED_FIELDS:
        if field not in rule_data:
            raise Exception(f"Validation error in '{rule_file}': Missing required field '{field}'")
    
    rule_id = rule_data["id"]
    if not isinstance(rule_id, int):
        raise Exception(f"Validation error in '{rule_file}': Field 'id' must be an integer, got {type(rule_id).__name__}")
    if rule_id < 0:
        raise Exception(f"Validation error in '{rule_file}': Field 'id' must be non-negative, got {rule_id}")
    
    description = rule_data["description"]
    if not isinstance(description, str):
        raise Exception(f"Validation error in '{rule_file}': Field 'description' must be a string, got {type(description).__name__}")
    
    action = rule_data["action"]
    if not isinstance(action, str):
        raise Exception(f"Validation error in '{rule_file}': Field 'action' must be a string, got {type(action).__name__}")
   
    if action not in ALLOWED_ACTIONS:
        raise Exception(f"Validation error in '{rule_file}': Invalid action '{action}'. Allowed actions: {ALLOWED_ACTIONS}")
    
    events = validate_events(rule_data["events"], rule_file)
    validate_detection(rule_data["detection"], rule_file)
    validate_fields_for_events(rule_data["detection"], events, rule_file)
    
    min_version = None
    if "min_version" in rule_data:
        min_version = validate_version_field(rule_data["min_version"], "min_version", rule_file)
    
    max_version = None
    if "max_version" in rule_data:
        max_version = validate_version_field(rule_data["max_version"], "max_version", rule_file)
    
    return SigmaRule(
        id=rule_id,
        description=description,
        action=action,
        events=events,
        detection=rule_data["detection"],
        source_file=rule_file,
        min_version=min_version,
        max_version=max_version
    )


def validate_rules_per_event_limit(rules: List[SigmaRule]) -> None:
    event_rule_counts: Dict[str, int] = {event: 0 for event in VALID_EVENT_TYPES}
    
    for rule in rules:
        for event in rule.events:
            event_rule_counts[event] += 1
    
    for event, count in event_rule_counts.items():
        if count > MAX_RULES_PER_MAP:
            raise Exception(f"Event type '{event}' has {count} rules, which exceeds the maximum of {MAX_RULES_PER_MAP} rules per event type")


def find_yml_files(directory: str) -> List[str]:
    yml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                yml_files.append(os.path.join(root, file))
    return sorted(yml_files)


def load_rule_file(file_path: str) -> Dict[str, Any]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if data is None:
            raise Exception(f"Parse error in '{file_path}': File is empty")
        if not isinstance(data, dict):
            raise Exception(f"Parse error in '{file_path}': Expected YAML dict at root, got {type(data).__name__}")
        return data
    except yaml.YAMLError as e:
        raise Exception(f"Parse error in '{file_path}': YAML parse error: {e}")
    except IOError as e:
        raise Exception(f"Parse error in '{file_path}': IO error: {e}")


def load_sigma_rules(
    directory: str,
    placeholders: Optional[Dict[str, List]] = None,
    placeholder_file: Optional[str] = None,
    field_mapping: Optional[Dict[str, str]] = None,
) -> List[SigmaRule]:
    if not os.path.isdir(directory):
        raise Exception(f"Directory does not exist: {directory}")
    
    yml_files = find_yml_files(directory)

    if placeholder_file:
        placeholder_abs = os.path.abspath(placeholder_file)
        yml_files = [f for f in yml_files if os.path.abspath(f) != placeholder_abs]

    if not yml_files:
        raise Exception(f"No .yml files found in {directory}")
    
    rules: List[SigmaRule] = []
    id_to_file: Dict[int, str] = {}
    
    for file_path in yml_files:
        rule_data = load_rule_file(file_path)

        if field_mapping and "detection" in rule_data and isinstance(rule_data["detection"], dict):
            apply_field_mapping_to_detection(rule_data["detection"], field_mapping)

        if "detection" in rule_data:
            rule_data["detection"] = expand_detection_placeholders(
                rule_data["detection"], placeholders, file_path)

        rule = validate_rule(rule_data, file_path)
        
        if rule.id in id_to_file:
            raise Exception(f"Duplicate rule id {rule.id}: found in '{id_to_file[rule.id]}' and '{file_path}'")
        
        id_to_file[rule.id] = file_path
        rules.append(rule)
    
    validate_rules_per_event_limit(rules)
    return rules


