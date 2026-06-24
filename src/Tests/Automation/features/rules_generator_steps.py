import json
from pathlib import Path

from pytest_bdd import given, when, then, parsers

from Utils.logger_utils import logger
from Utils.rules_generator_utils import (
    assert_config_valid,
    build_memory_payload,
    run_file_mode,
    run_memory_mode,
)

_VALID_RULE = (
    "id: 1\n"
    "description: test\n"
    "action: ALLOW_EVENT\n"
    "events:\n  - EXEC\n"
    "detection:\n"
    "  selection:\n"
    "    process.file.path: /test\n"
    "  condition: selection\n"
)

_CORRUPT_PAYLOADS = {
    "duplicate id": (
        {
            "placeholders_yml": "",
            "field_mapping_yml": "",
            "rules": [_VALID_RULE, _VALID_RULE],
        },
        "Duplicate rule id",
    ),
    "schema validation": (
        {
            # missing required "placeholders_yml"
            "field_mapping_yml": "",
            "rules": [_VALID_RULE],
        },
        "schema validation",
    ),
    "missing placeholder": (
        {
            "placeholders_yml": "other_placeholder:\n  - value\n",
            "field_mapping_yml": "",
            "rules": [
                "id: 1\n"
                "description: test\n"
                "action: ALLOW_EVENT\n"
                "events:\n  - EXEC\n"
                "detection:\n"
                "  selection:\n"
                "    process.file.path|expand: '%missing_placeholder%'\n"
                "  condition: selection\n"
            ],
        },
        "missing_placeholder",
    ),
    "bad mapping": (
        {
            "placeholders_yml": "",
            "field_mapping_yml": "fields:\n  event.custom: nonexistent.owlsm.field\n",
            "rules": [_VALID_RULE],
        },
        "not a valid owLSM rule field",
    ),
    "missing id": (
        {
            "placeholders_yml": "",
            "field_mapping_yml": "",
            "rules": [
                "description: test\n"
                "action: ALLOW_EVENT\n"
                "events:\n  - EXEC\n"
                "detection:\n"
                "  selection:\n"
                "    process.file.path: /test\n"
                "  condition: selection\n"
            ],
        },
        "id",
    ),
    "fieldref to nonexistent field": (
        {
            "placeholders_yml": "",
            "field_mapping_yml": "",
            "rules": [
                "id: 1\n"
                "description: test\n"
                "action: ALLOW_EVENT\n"
                "events:\n  - EXEC\n"
                "detection:\n"
                "  selection:\n"
                "    process.file.path|fieldref: nonexistent.field.xyz\n"
                "  condition: selection\n"
            ],
        },
        "nonexistent.field.xyz",
    ),
}


@given(parsers.parse('I run rules_generator in file mode and write to "{path}"'))
@when(parsers.parse('I run rules_generator in file mode and write to "{path}"'))
@then(parsers.parse('I run rules_generator in file mode and write to "{path}"'))
def run_rules_generator_file_mode(path):
    run_file_mode(Path(path))


@given(parsers.parse('I run rules_generator in memory mode and write to "{path}"'))
@when(parsers.parse('I run rules_generator in memory mode and write to "{path}"'))
@then(parsers.parse('I run rules_generator in memory mode and write to "{path}"'))
def run_rules_generator_memory_mode(path):
    config, exit_code, stderr = run_memory_mode(build_memory_payload())
    assert exit_code == 0, f"rules_generator memory mode failed (exit {exit_code}):\n{stderr}"
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


@given(parsers.parse('the config at "{path}" is valid'))
@when(parsers.parse('the config at "{path}" is valid'))
@then(parsers.parse('the config at "{path}" is valid'))
def validate_config_at_path(path):
    with open(path) as f:
        config = json.load(f)
    assert_config_valid(config)


@given(parsers.parse('"{path1}" and "{path2}" are identical json files'))
@when(parsers.parse('"{path1}" and "{path2}" are identical json files'))
@then(parsers.parse('"{path1}" and "{path2}" are identical json files'))
def json_files_are_identical(path1, path2):
    with open(path1) as f:
        config1 = json.load(f)
    with open(path2) as f:
        config2 = json.load(f)
    assert config1 == config2, f"JSON files differ:\n  {path1}\n  {path2}"


@given(parsers.parse('rules_generator memory mode fails with "{reason}"'))
@when(parsers.parse('rules_generator memory mode fails with "{reason}"'))
@then(parsers.parse('rules_generator memory mode fails with "{reason}"'))
def rules_generator_memory_fails_with(reason):
    assert reason in _CORRUPT_PAYLOADS, f"Unknown failure reason: '{reason}'"
    payload, expected_stderr_substr = _CORRUPT_PAYLOADS[reason]

    _, exit_code, stderr = run_memory_mode(payload)

    assert exit_code != 0, (
        f"Expected rules_generator to fail for '{reason}' but it exited 0"
    )
    assert expected_stderr_substr in stderr, (
        f"Expected stderr to contain '{expected_stderr_substr}' for '{reason}'.\n"
        f"Actual stderr:\n{stderr}"
    )
    logger.log_info(f"rules_generator correctly failed for '{reason}': exit={exit_code}")
