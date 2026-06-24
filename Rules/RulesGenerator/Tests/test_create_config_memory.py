import io
import json
import sys

import pytest

from create_config import generate_rules_json_from_memory, main, parse_arguments
from memory_input_handler import MemoryInput, MemoryInputHandler


VALID_RULE_YAML = """
id: 1
title: "Memory mode rule"
description: "Valid rule for memory mode"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
  sel:
    process.file.filename: "bash"
  condition: sel
"""


def test_memory_input_handler_parses_stdin(monkeypatch):
    payload = {
        "placeholders_yml": "shell_names:\n  - bash\n  - zsh\n",
        "field_mapping_yml": "fields:\n  Image: process.file.filename\n",
        "rules": [VALID_RULE_YAML],
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

    handler = MemoryInputHandler.from_stdin()

    assert handler.get_rules() == [VALID_RULE_YAML]
    assert handler.get_placeholders() == {"shell_names": ["bash", "zsh"]}
    assert handler.get_field_mapping() == {"Image": "process.file.filename"}


def test_parse_arguments_memory_rejects_file_flags(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["create_config.py", "--memory", "-d", "/tmp/rules"])

    with pytest.raises(SystemExit):
        parse_arguments()


def test_memory_input_handler_rejects_payload_not_matching_schema(monkeypatch):
    payload = {
        "field_mapping_yml": "",
        "rules": [VALID_RULE_YAML],
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

    with pytest.raises(Exception, match="schema validation"):
        MemoryInputHandler.from_stdin()


def test_main_memory_writes_final_config_to_stdout(monkeypatch):
    payload = {
        "placeholders_yml": "",
        "field_mapping_yml": "",
        "rules": [VALID_RULE_YAML],
    }

    fake_stdout = io.StringIO()
    fake_stderr = io.StringIO()

    monkeypatch.setattr(sys, "argv", ["create_config.py", "--memory"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    monkeypatch.setattr(sys, "stderr", fake_stderr)

    main()

    output = json.loads(fake_stdout.getvalue())
    assert "rules" in output
    assert "rules" in output["rules"]
    assert len(output["rules"]["rules"]) == 1


def test_generate_rules_json_from_memory_raises_on_empty_rules():
    memory_input_handler = MemoryInputHandler(
        MemoryInput(
            placeholders_yml="",
            field_mapping_yml="",
            rules=[],
        )
    )

    with pytest.raises(RuntimeError):
        generate_rules_json_from_memory(memory_input_handler)
