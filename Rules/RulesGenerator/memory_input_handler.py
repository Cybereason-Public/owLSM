import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
import yaml

from constants import RULE_FIELD_TYPES
from field_mapping import apply_field_mapping_to_detection
from placeholder_expander import expand_detection_placeholders
from sigma_rule_loader import SigmaRule, validate_rule, validate_rules_per_event_limit


def _resolve_first_existing_path(candidates: List[Path]) -> Optional[Path]:
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.exists():
            return resolved
    return None


def _memory_schema_candidates() -> List[Path]:
    file_name = "memory_json_schema.json"
    script_dir = Path(__file__).resolve().parent
    exe_dir = Path(sys.executable).resolve().parent

    candidates = [
        script_dir / file_name,
        (exe_dir / ".." / "rules_generator" / file_name).resolve(),
    ]

    if hasattr(sys, "_MEIPASS"):
        meipass_dir = Path(getattr(sys, "_MEIPASS")).resolve()
        candidates.append((meipass_dir / file_name).resolve())

    return candidates


@dataclass
class MemoryInput:
    placeholders_yml: str
    field_mapping_yml: str
    rules: List[str]


class MemoryInputHandler:
    def __init__(self, memory_input: MemoryInput):
        self._memory_input = memory_input

    @classmethod
    def from_stdin(cls):
        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            raise Exception("Memory mode stdin is empty")

        payload = json.loads(raw_stdin)
        _validate_memory_input_schema(payload)

        return cls(
            MemoryInput(
                placeholders_yml=payload["placeholders_yml"],
                field_mapping_yml=payload["field_mapping_yml"],
                rules=payload["rules"],
            )
        )

    def get_placeholders(self) -> Optional[Dict[str, List]]:
        if not self._memory_input.placeholders_yml.strip():
            return None
        return _parse_placeholders_yaml(self._memory_input.placeholders_yml)

    def get_field_mapping(self) -> Optional[Dict[str, str]]:
        if not self._memory_input.field_mapping_yml.strip():
            return None
        return _parse_field_mapping_yaml(self._memory_input.field_mapping_yml)

    def get_rules(self) -> List[str]:
        return self._memory_input.rules

    def load_rules(
        self,
        placeholders: Optional[Dict[str, List]] = None,
        field_mapping: Optional[Dict[str, str]] = None,
    ) -> List[SigmaRule]:
        if not self._memory_input.rules:
            raise Exception("No rules were provided in memory input")

        rules: List[SigmaRule] = []
        id_to_source: Dict[int, str] = {}

        for index, rule_yaml in enumerate(self._memory_input.rules):
            source_name = f"stdin.rules[{index}]"
            rule_data = _parse_rule_yaml(rule_yaml, source_name, index)

            if field_mapping and "detection" in rule_data and isinstance(rule_data["detection"], dict):
                apply_field_mapping_to_detection(rule_data["detection"], field_mapping)

            if "detection" in rule_data:
                rule_data["detection"] = expand_detection_placeholders(
                    rule_data["detection"],
                    placeholders,
                    source_name,
                )

            rule = validate_rule(rule_data, source_name)
            if rule.id in id_to_source:
                raise Exception(f"Duplicate rule id {rule.id}: found in '{id_to_source[rule.id]}' and '{source_name}'")
            id_to_source[rule.id] = source_name
            rules.append(rule)

        validate_rules_per_event_limit(rules)
        return rules


def _parse_rule_yaml(rule_yaml: Any, source_name: str, index: int) -> Dict[str, Any]:
    if not isinstance(rule_yaml, str):
        raise Exception(
            f"Memory input rule at index {index} must be a YAML string, "
            f"got {type(rule_yaml).__name__}"
        )
    if not rule_yaml.strip():
        raise Exception(f"Memory input rule '{source_name}' is empty")

    try:
        data = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        raise Exception(f"Parse error in '{source_name}': YAML parse error: {e}")

    if data is None:
        raise Exception(f"Parse error in '{source_name}': File is empty")
    if not isinstance(data, dict):
        raise Exception(f"Parse error in '{source_name}': Expected YAML dict at root, got {type(data).__name__}")

    return data


def _parse_placeholders_yaml(yaml_text: str) -> Dict[str, List]:
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise Exception(f"Failed to parse placeholder input 'stdin.placeholders_yml': {e}")

    if data is None:
        raise Exception("Placeholder input 'stdin.placeholders_yml' is empty")
    if not isinstance(data, dict):
        raise Exception(
            "Placeholder input 'stdin.placeholders_yml' must contain a YAML mapping, "
            f"got {type(data).__name__}")

    for name, values in data.items():
        if not isinstance(name, str):
            raise Exception(f"Placeholder name must be a string, got {type(name).__name__}")
        if not isinstance(values, list):
            raise Exception(
                f"Placeholder '{name}' must map to a list, got {type(values).__name__}")
        if len(values) == 0:
            raise Exception(f"Placeholder '{name}' must have at least one value (empty lists not allowed)")
        for i, value in enumerate(values):
            if not isinstance(value, (str, int, float)):
                raise Exception(
                    f"Placeholder '{name}' item {i}: values must be strings or numbers, "
                    f"got {type(value).__name__}")

    return data


def _parse_field_mapping_yaml(yaml_text: str) -> Dict[str, str]:
    try:
        data = yaml.safe_load(yaml_text)
    except Exception as e:
        raise Exception(f"Field mapping input 'stdin.field_mapping_yml': {e}") from e

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise Exception(
            "Field mapping input 'stdin.field_mapping_yml': expected a YAML mapping at root, "
            f"got {type(data).__name__}")

    allowed_destinations = {key for key, value in RULE_FIELD_TYPES.items() if value != "none"}
    mapping: Dict[str, str] = {}

    for source, dest in data.items():
        if not isinstance(source, str) or not isinstance(dest, str):
            raise Exception(
                "Field mapping input 'stdin.field_mapping_yml': mapping keys and values must be strings, "
                f"got {type(source).__name__} and {type(dest).__name__}"
            )
        if dest not in allowed_destinations:
            raise Exception(
                "Field mapping input 'stdin.field_mapping_yml': "
                f"destination field '{dest}' is not a valid owLSM rule field"
            )
        mapping[source] = dest

    return mapping


def _validate_memory_input_schema(payload: Any) -> None:
    candidates = _memory_schema_candidates()
    schema_path = _resolve_first_existing_path(candidates)
    if schema_path is None:
        candidate_text = ", ".join(str(path) for path in candidates)
        raise FileNotFoundError(f"memory_json_schema.json not found in expected paths: {candidate_text}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    try:
        jsonschema.validate(instance=payload, schema=schema)
    except jsonschema.ValidationError as e:
        raise Exception(f"Memory mode input failed schema validation: {e.message}") from e
