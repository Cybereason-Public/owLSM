#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

_RULES_GENERATOR_DIR = Path(__file__).resolve().parent.parent.parent / "Rules" / "RulesGenerator"


def _ensure_rules_generator_on_path() -> None:
    if not getattr(sys, "frozen", False) and str(_RULES_GENERATOR_DIR) not in sys.path:
        sys.path.insert(0, str(_RULES_GENERATOR_DIR))


def _rules_generator_field_mapping():
    _ensure_rules_generator_on_path()
    from field_mapping import apply_field_mapping_to_detection, load_field_mapping_file  # type: ignore[import-not-found]
    return apply_field_mapping_to_detection, load_field_mapping_file


def _rules_generator_memory_handler():
    _ensure_rules_generator_on_path()
    from memory_input_handler import MemoryInputHandler, _parse_rule_yaml  # type: ignore[import-not-found]
    return MemoryInputHandler, _parse_rule_yaml


class FieldMappingConverter:

    @staticmethod
    def apply(rule_data: Dict[str, Any], mapping: Any) -> None:
        apply_field_mapping_to_detection, _ = _rules_generator_field_mapping()
        if "detection" not in rule_data or not isinstance(rule_data["detection"], dict):
            return
        apply_field_mapping_to_detection(rule_data["detection"], mapping)

    @staticmethod
    def load(mapping_path: Path) -> Any:
        _, load_field_mapping_file = _rules_generator_field_mapping()
        return load_field_mapping_file(str(mapping_path.resolve()))


class StatusValidator:

    ALLOWED_STATUSES: Set[str] = {"stable", "test", "experimental"}
    REPORT_ONLY_STATUSES: Set[str] = {"test", "experimental"}

    @staticmethod
    def validate(rule_data: Dict[str, Any], rule_file: str) -> None:
        if "status" not in rule_data:
            raise Exception(f"Validation error in '{rule_file}': missing required field 'status'")

        status = rule_data["status"]
        if not isinstance(status, str):
            raise Exception(f"Validation error in '{rule_file}': field 'status' must be a string, got {type(status).__name__}")

        if status not in StatusValidator.ALLOWED_STATUSES:
            raise Exception( f"Validation error in '{rule_file}': status must be one of {sorted(StatusValidator.ALLOWED_STATUSES)}, got {status!r}")

        if status in StatusValidator.REPORT_ONLY_STATUSES:
            actions = rule_data.get("actions", [])
            if isinstance(actions, list):
                for idx, item in enumerate(actions):
                    if isinstance(item, dict) and item.get("mode") != "report":
                        raise Exception(f"Validation error in '{rule_file}': status {status!r} requires all actions[*].mode to be 'report', got {item.get('mode')!r} at index {idx}")


class ActionsConverter:

    @staticmethod
    def convert(rule_data: Dict[str, Any], rule_file: str) -> None:
        if "actions" not in rule_data:
            raise Exception(f"Validation error in '{rule_file}': missing required field 'actions'")

        actions = rule_data["actions"]
        if not isinstance(actions, list) or len(actions) == 0:
            raise Exception(f"Validation error in '{rule_file}': field 'actions' must be a non-empty list")

        modes: Set[str] = set()
        for idx, item in enumerate(actions):
            if not isinstance(item, dict):
                raise Exception(f"Validation error in '{rule_file}': actions[{idx}] must be a mapping, got {type(item).__name__}")

            if set(item.keys()) != {"mode"}:
                raise Exception(f"Validation error in '{rule_file}': actions[{idx}] must contain only the key 'mode'")

            mode = item["mode"]
            if not isinstance(mode, str):
                raise Exception(f"Validation error in '{rule_file}': actions[{idx}].mode must be a string, got {type(mode).__name__}")

            if mode not in ("prevent", "report"):
                raise Exception(f"Validation error in '{rule_file}': actions[{idx}].mode must be 'prevent' or 'report', got {mode!r}")

            modes.add(mode)

        if "prevent" in modes:
            rule_data["action"] = "BLOCK_EVENT"
        else:
            rule_data["action"] = "ALLOW_EVENT"

        del rule_data["actions"]


class LogsourceEventsConverter:

    EVENT_MAPPING: Dict[str, str] = {
        "process_created": "EXEC",
        "process_creation": "EXEC",
        "process_ended": "EXIT",
        "file_created": "FILE_CREATE",
        "file_deleted": "UNLINK",
        "file_modified": "WRITE",
        "file_read": "READ",
        "file_renamed": "RENAME",
        "file_permission_changed": "CHMOD",
        "file_owner_changed": "CHOWN",
        "network_connection_attempted": "NETWORK",
    }

    # file_created/file_deleted become directory events when event.file.type is a directory
    DIRECTORY_EVENT: Dict[str, str] = {"file_created": "MKDIR", "file_deleted": "RMDIR"}
    DIRECTORY_TYPE_VALUES: Set[str] = {"DIRECTORY", "DIR"}

    @staticmethod
    def _collect_file_type_values(detection: Any) -> List[Any]:
        values: List[Any] = []
        if not isinstance(detection, dict):
            return values
        for name, selection in detection.items():
            if name == "condition":
                continue
            entries = selection if isinstance(selection, list) else [selection]
            for entry in entries:
                if isinstance(entry, dict):
                    for key, val in entry.items():
                        if key.split("|")[0] == "event.file.type":
                            values.append(val)
        return values

    @staticmethod
    def _resolve_file_event(logsource_value: str, default_event: str, detection: Any, rule_file: str) -> str:
        file_types = LogsourceEventsConverter._collect_file_type_values(detection)
        if len(file_types) > 1:
            raise Exception(f"Validation error in '{rule_file}': rule has {len(file_types)} 'event.file.type' fields; at most one is allowed")
        if len(file_types) == 0:
            return default_event
        value = file_types[0]
        if isinstance(value, list):
            if any(v in LogsourceEventsConverter.DIRECTORY_TYPE_VALUES for v in value):
                raise Exception(f"Validation error in '{rule_file}': 'event.file.type' list must not contain {sorted(LogsourceEventsConverter.DIRECTORY_TYPE_VALUES)}")
            return default_event
        if value in LogsourceEventsConverter.DIRECTORY_TYPE_VALUES:
            return LogsourceEventsConverter.DIRECTORY_EVENT[logsource_value]
        return default_event

    @staticmethod
    def convert(rule_data: Dict[str, Any], rule_file: str) -> None:
        if "logsource" not in rule_data:
            raise Exception(f"Validation error in '{rule_file}': missing required field 'logsource'")

        logsource = rule_data["logsource"]
        if not isinstance(logsource, dict):
            raise Exception(f"Validation error in '{rule_file}': field 'logsource' must be a mapping, got {type(logsource).__name__}")

        if "event.action" in logsource:
            field_name = "event.action"
        elif "category" in logsource:
            field_name = "category"
        else:
            raise Exception(f"Validation error in '{rule_file}': logsource missing 'event.action' (or 'category')")

        value = logsource[field_name]
        if value not in LogsourceEventsConverter.EVENT_MAPPING:
            raise Exception(f"Validation error in '{rule_file}': logsource.{field_name} must be one of {sorted(LogsourceEventsConverter.EVENT_MAPPING)}, got {value!r}")

        event = LogsourceEventsConverter.EVENT_MAPPING[value]
        if value in LogsourceEventsConverter.DIRECTORY_EVENT:
            event = LogsourceEventsConverter._resolve_file_event(value, event, rule_data.get("detection"), rule_file)

        del rule_data["logsource"]
        rule_data["events"] = [event]


def _find_rule_files(input_dir: Path) -> List[Path]:
    paths: List[Path] = []
    for p in input_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
            paths.append(p)
    return sorted(paths)


def _load_yaml(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        raise Exception(f"Parse error in '{path}': file is empty")
    if not isinstance(data, dict):
        raise Exception(f"Parse error in '{path}': expected YAML mapping at root, got {type(data).__name__}")
    return data


def _dump_yaml(data: Dict[str, Any]) -> str:
    return yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(_dump_yaml(data))


def _convert_rule_data(rule_data: Dict[str, Any], field_mapping: Any, source_name: str) -> None:
    StatusValidator.validate(rule_data, source_name)
    ActionsConverter.convert(rule_data, source_name)
    LogsourceEventsConverter.convert(rule_data, source_name)
    if field_mapping is not None:
        FieldMappingConverter.apply(rule_data, field_mapping)


def _run_memory_mode() -> None:
    MemoryInputHandler, _parse_rule_yaml = _rules_generator_memory_handler()
    handler = MemoryInputHandler.from_stdin()

    # placeholders_yml is part of the shared payload contract but has no meaning
    # for the company-format conversion, so it is intentionally ignored here.
    field_mapping = handler.get_field_mapping()
    rules = handler.get_rules()
    if not rules:
        raise Exception("No rules were provided in memory input")

    converted: List[str] = []
    for index, rule_yaml in enumerate(rules):
        source_name = f"stdin.rules[{index}]"
        rule_data = _parse_rule_yaml(rule_yaml, source_name, index)
        _convert_rule_data(rule_data, field_mapping, source_name)
        converted.append(_dump_yaml(rule_data))

    json.dump(converted, sys.stdout)
    sys.stdout.write("\n")


def _run_file_mode(input_dir: Path, output_dir: Path, field_mapping_path: Optional[Path]) -> None:
    if not input_dir.is_dir():
        raise Exception(f"Input directory does not exist or is not a directory: {input_dir}")

    rule_files = _find_rule_files(input_dir)
    if not rule_files:
        raise Exception(f"No .yml or .yaml files found under {input_dir}")

    field_mapping = None
    if field_mapping_path is not None:
        if not field_mapping_path.is_file():
            raise Exception(f"Field mapping file does not exist or is not a file: {field_mapping_path}")
        field_mapping = FieldMappingConverter.load(field_mapping_path)

    for src in rule_files:
        rel = src.relative_to(input_dir)
        dst = output_dir / rel
        rule_data = _load_yaml(src)
        _convert_rule_data(rule_data, field_mapping, str(src))
        _write_yaml(dst, rule_data)


def main() -> None:
    try:
        parser = argparse.ArgumentParser(description="Convert company YAML to owLSM shape: actions/logsource/fields to owLSM YAML.")
        parser.add_argument("-i", "--input-directory", type=Path, help="Directory containing .yml / .yaml rules (searched recursively)")
        parser.add_argument("-o", type=Path, help="Directory to write converted rules (mirrors relative paths from input root)")
        parser.add_argument("-m", "--field-mapping", type=Path, help="YAML file: field name and enum value mappings (supports 'fields:' and 'enums:' sections)")
        parser.add_argument("--memory", action="store_true", help="Read a JSON payload from stdin (same shape as rules_generator --memory: "
            "placeholders_yml/field_mapping_yml/rules) and write the converted rules as a JSON "
            "array of YAML strings to stdout. For users that dont want their rules on the disk.",
        )
        args = parser.parse_args()

        if args.memory:
            if any(value is not None for value in (args.input_directory, args.o, args.field_mapping)):
                parser.error("--memory cannot be used with file-based flags (-i/-o/-m)")
            _run_memory_mode()
            return

        if args.input_directory is None or args.o is None:
            parser.error("file mode requires -i/--input-directory and -o")

        field_mapping_path = args.field_mapping.resolve() if args.field_mapping else None
        _run_file_mode(args.input_directory.resolve(), args.o.resolve(), field_mapping_path)

    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
