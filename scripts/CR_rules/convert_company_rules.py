#!/usr/bin/env python3
"""Normalize company Sigma-like YAML: actions -> action, logsource -> events."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml


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

    @staticmethod
    def convert(rule_data: Dict[str, Any], rule_file: str) -> None:
        if "logsource" not in rule_data:
            raise Exception(f"Validation error in '{rule_file}': missing required field 'logsource'")

        logsource = rule_data["logsource"]
        if not isinstance(logsource, dict):
            raise Exception(f"Validation error in '{rule_file}': field 'logsource' must be a mapping, got {type(logsource).__name__}")

        if "category" not in logsource:
            raise Exception(f"Validation error in '{rule_file}': logsource missing 'category'")

        category = logsource["category"]
        if category != "process_creation":
            raise Exception(f"Validation error in '{rule_file}': logsource.category must be 'process_creation', got {category!r}")

        del rule_data["logsource"]
        rule_data["events"] = ["EXEC"]


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


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def main() -> None:
    try:
        parser = argparse.ArgumentParser(description="Convert company actions/logsource to owLSM action/events YAML.")
        parser.add_argument("-i", "--input-directory", required=True, type=Path, help="Directory containing .yml / .yaml rules (searched recursively)")
        parser.add_argument("-o", required=True, type=Path, help="Directory to write converted rules (mirrors relative paths from input root)")
        args = parser.parse_args()

        input_dir = args.input_directory.resolve()
        output_dir = args.output_directory.resolve()

        if not input_dir.is_dir():
            raise Exception(f"Input directory does not exist or is not a directory: {input_dir}")

        rule_files = _find_rule_files(input_dir)
        if not rule_files:
            raise Exception(f"No .yml or .yaml files found under {input_dir}")

        for src in rule_files:
            rel = src.relative_to(input_dir)
            dst = output_dir / rel
            rule_data = _load_yaml(src)
            ActionsConverter.convert(rule_data, str(src))
            LogsourceEventsConverter.convert(rule_data, str(src))
            _write_yaml(dst, rule_data)

    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
