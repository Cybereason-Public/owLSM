import json
from pathlib import Path
from typing import Optional

from globals.system_related_globals import system_globals
from Utils.logger_utils import logger
from Utils.process_utils import run_command_sync

_SIGMA_DIR = system_globals.RESOURCES_PATH / "sigma_rules"
_PLACEHOLDERS_FILE = _SIGMA_DIR / "placeholder_values.yml"
_FIELD_MAPPING_FILE = system_globals.RESOURCES_PATH / "field_mapping.yml"
_BINARY = system_globals.AUTOMATION_ROOT_DIR / "owlsm" / "bin" / "rules_generator"
_BASE_CONFIG = system_globals.AUTOMATION_ROOT_DIR / "owlsm" / "rules_generator" / "base_config.json"


def run_file_mode(output_path: Path) -> None:
    stderr_out = []
    command = (
        f"{_BINARY} -d {_SIGMA_DIR} -c {_BASE_CONFIG} -o {output_path}"
        f" -p {_PLACEHOLDERS_FILE} -m {_FIELD_MAPPING_FILE}"
    )
    success = run_command_sync(command, stderr_out=stderr_out, expect_exit_code=0)
    stderr = stderr_out[0] if stderr_out else ""
    if not success:
        logger.log_error(f"rules_generator file mode failed:\n{stderr}")
    assert success, f"rules_generator file mode failed:\n{stderr}"


def run_memory_mode(payload: dict) -> tuple[Optional[dict], int, str]:
    """Returns (parsed_config_or_None, exit_code, stderr)."""
    stdout_out, stderr_out = [], []
    success = run_command_sync(
        f"{_BINARY} --memory",
        stdin_data=json.dumps(payload),
        stdout_out=stdout_out,
        stderr_out=stderr_out,
        expect_exit_code=0,
    )
    stderr = stderr_out[0] if stderr_out else ""
    config = None
    if success:
        config = json.loads(stdout_out[0])
    else:
        logger.log_error(f"rules_generator memory mode failed:\n{stderr}")
    return config, 0 if success else 1, stderr


def build_memory_payload() -> dict:
    rules = [
        f.read_text()
        for f in sorted(_SIGMA_DIR.glob("*.yml"))
        if f.name != _PLACEHOLDERS_FILE.name
    ]
    return {
        "placeholders_yml": _PLACEHOLDERS_FILE.read_text(),
        "field_mapping_yml": _FIELD_MAPPING_FILE.read_text(),
        "rules": rules,
    }


def count_sigma_rules() -> int:
    return sum(
        1 for f in _SIGMA_DIR.glob("*.yml")
        if "detection" in f.read_text() and "condition" in f.read_text()
    )


def assert_config_valid(config: dict) -> None:
    rules_section = config.get("rules", {})

    expected_count = count_sigma_rules()
    actual_count = len({r["id"] for r in rules_section.get("rules", [])})
    assert actual_count == expected_count, (
        f"Rule count mismatch: expected {expected_count} unique rule IDs, got {actual_count}"
    )

    id_to_string = rules_section.get("id_to_string", {})
    chmod_count = sum(1 for e in id_to_string.values() if e.get("value") == "chmod")
    assert chmod_count == 1, f"'chmod' should appear once in id_to_string, got {chmod_count}"
