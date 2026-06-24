"""Map external rule field names and enum values to owLSM equivalents (structured rewrite on detection).

Field mapping files use a sectioned format with two optional top-level keys:

    fields:
        ImagePath: process.file.path
        ParentCommandLine: parent_process.cmd
    enums:
        DIR: DIRECTORY
        FILE: REGULAR_FILE
        INBOUND: INCOMING

- ``fields`` maps source field names to owLSM field names.
- ``enums`` maps source enum values to owLSM enum values (applied globally across all fields).

Both sections are optional. An empty file is valid and produces empty mappings.
"""

from __future__ import annotations

from typing import Any, Dict

import yaml

from constants import RULE_FIELD_TYPES


class FieldMapping(dict):
    """Combined field-name and enum-value mapping.

    Behaves as a plain dict keyed by source field name (backward-compatible with
    all existing callers). Carries enum value mappings as an extra attribute,
    applied automatically by apply_field_mapping_to_detection.
    """

    def __init__(self, fields: Dict[str, str] = None, enums: Dict[str, str] = None):
        super().__init__(fields or {})
        self._enums: Dict[str, str] = enums or {}

    @property
    def enums(self) -> Dict[str, str]:
        return self._enums


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


def _remap_enum_values_in_selection(item: Dict[str, Any], enums: Dict[str, str]) -> None:
    for field_key, values in item.items():
        if _field_key_has_fieldref(field_key):
            continue
        if isinstance(values, str):
            item[field_key] = enums.get(values, values)
        elif isinstance(values, list):
            item[field_key] = [enums.get(v, v) if isinstance(v, str) else v for v in values]


def _apply_enum_mapping_to_detection(detection: Dict[str, Any], enums: Dict[str, str]) -> None:
    for selection_name, selection_value in detection.items():
        if selection_name == "condition":
            continue
        if isinstance(selection_value, dict):
            _remap_enum_values_in_selection(selection_value, enums)
        elif isinstance(selection_value, list):
            for entry in selection_value:
                if isinstance(entry, dict):
                    _remap_enum_values_in_selection(entry, enums)


def apply_field_mapping_to_detection(detection: Dict[str, Any], mapping: Dict[str, str]) -> None:
    """Rewrite detection dict keys and fieldref targets in place.

    If mapping is a FieldMapping, also rewrites enum values before key remapping.
    """
    if not mapping:
        return

    if isinstance(mapping, FieldMapping) and mapping.enums:
        _apply_enum_mapping_to_detection(detection, mapping.enums)

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


def _assert_sectioned(data: Dict[str, Any], source: str) -> None:
    if data and "fields" not in data and "enums" not in data:
        raise Exception(
            f"{source}: must use sectioned format with 'fields:' and/or 'enums:' keys"
        )


def parse_field_mapping_data(data: Any, source: str) -> Dict[str, str]:
    """Extract field name mappings from already-parsed YAML data."""
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise Exception(f"{source}: expected a YAML mapping at root, got {type(data).__name__}")

    _assert_sectioned(data, source)

    raw = data.get("fields")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise Exception(f"{source}: 'fields' section must be a mapping")

    allowed = _get_valid_mapping_destinations()
    mapping: Dict[str, str] = {}
    for src, dst in raw.items():
        if not isinstance(src, str) or not isinstance(dst, str):
            raise Exception(
                f"{source}: mapping keys and values must be strings, "
                f"got {type(src).__name__} and {type(dst).__name__}"
            )
        if dst not in allowed:
            raise Exception(f"{source}: destination field '{dst}' is not a valid owLSM rule field")
        mapping[src] = dst

    return mapping


def parse_value_mapping_data(data: Any, source: str) -> Dict[str, str]:
    """Extract enum value mappings from already-parsed YAML data."""
    if not isinstance(data, dict):
        return {}

    _assert_sectioned(data, source)

    enums = data.get("enums")
    if enums is None:
        return {}
    if not isinstance(enums, dict):
        raise Exception(f"{source}: 'enums' section must be a mapping")

    mapping: Dict[str, str] = {}
    for src, dst in enums.items():
        if not isinstance(src, str) or not isinstance(dst, str):
            raise Exception(f"{source}: 'enums' entries must be string -> string")
        mapping[src] = dst

    return mapping


def _load_raw(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        raise Exception(f"Field mapping file '{path}': {e}") from e


def load_field_mapping_file(path: str) -> FieldMapping:
    data = _load_raw(path)
    source = f"Field mapping file '{path}'"
    return FieldMapping(
        fields=parse_field_mapping_data(data, source),
        enums=parse_value_mapping_data(data, source),
    )
