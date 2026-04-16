"""Map external rule field names to owLSM field names (structured rewrite on detection)."""

from __future__ import annotations

from typing import Any, Dict

import yaml

from constants import RULE_FIELD_TYPES


def _is_keyword_selection(selection_value: Any) -> bool:
    if isinstance(selection_value, list):
        return len(selection_value) > 0 and all(isinstance(item, str) for item in selection_value)
    if isinstance(selection_value, dict) and len(selection_value) == 1 and "|all" in selection_value:
        inner = selection_value["|all"]
        return (
            isinstance(inner, list)
            and len(inner) > 0
            and all(isinstance(item, str) for item in inner)
        )
    return False


def _field_key_has_fieldref(field_key: str) -> bool:
    parts = field_key.split("|")
    return any(p.lower() == "fieldref" for p in parts[1:])


def _remap_field_key(field_key: str, mapping: Dict[str, str]) -> str:
    parts = field_key.split("|")
    base = parts[0]
    if base in mapping:
        parts[0] = mapping[base]
    return "|".join(parts)


def _remap_fieldref_scalar(field_key: str, values: Any, mapping: Dict[str, str]) -> Any:
    if not _field_key_has_fieldref(field_key):
        return values
    if isinstance(values, str) and values in mapping:
        return mapping[values]
    return values


def _remap_selection_dict(item: Dict[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for field_key, values in item.items():
        new_key = _remap_field_key(field_key, mapping)
        out[new_key] = _remap_fieldref_scalar(field_key, values, mapping)
    return out


def apply_field_mapping_to_detection(detection: Dict[str, Any], mapping: Dict[str, str]) -> None:
    """Rewrite detection dict keys and fieldref targets in place."""
    if not mapping:
        return

    for selection_name, selection_value in list(detection.items()):
        if selection_name == "condition":
            continue
        if _is_keyword_selection(selection_value):
            continue
        if isinstance(selection_value, dict):
            detection[selection_name] = _remap_selection_dict(selection_value, mapping)
        elif isinstance(selection_value, list):
            detection[selection_name] = [
                _remap_selection_dict(entry, mapping) if isinstance(entry, dict) else entry
                for entry in selection_value
            ]


def _get_valid_mapping_destinations() -> set:
    return {k for k, v in RULE_FIELD_TYPES.items() if v != "none"}


def load_field_mapping_file(path: str) -> Dict[str, str]:
    allowed = _get_valid_mapping_destinations()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise Exception(f"Field mapping file '{path}': {e}") from e

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise Exception(f"Field mapping file '{path}': expected a YAML mapping at root, got {type(data).__name__}")

    mapping: Dict[str, str] = {}
    for source, dest in data.items():
        if not isinstance(source, str) or not isinstance(dest, str):
            raise Exception(
                f"Field mapping file '{path}': mapping keys and values must be strings, got {type(source).__name__} and {type(dest).__name__}"
            )
        if dest not in allowed:
            raise Exception(f"Field mapping file '{path}': destination field '{dest}' is not a valid owLSM rule field")

        mapping[source] = dest

    return mapping
