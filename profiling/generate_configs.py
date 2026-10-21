#!/usr/bin/env python3
"""Write the no-match and yes-match rules and compile them into the two test configs.

config_yes_rule_match.json carries every no-match rule plus the one matching rule, so a
"yes match" run still pays the cost of evaluating all the non-matching rules too.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROFILING_DIR = Path(__file__).resolve().parent
REPO_DIR = PROFILING_DIR.parent
GENERATOR_DIR = REPO_DIR / "Rules" / "RulesGenerator"
BASE_CONFIG = GENERATOR_DIR / "base_config.json"
NO_MATCH_RULES_DIR = PROFILING_DIR / "resources" / "rules" / "no_match"
NO_MATCH_OUTPUT = PROFILING_DIR / "resources" / "config" / "no_rule_matches_config.json"
YES_MATCH_RULES_DIR = PROFILING_DIR / "resources" / "rules" / "yes_match"
YES_MATCH_OUTPUT = PROFILING_DIR / "resources" / "config" / "config_yes_rule_match.json"
VENV_PYTHON = GENERATOR_DIR / "venv" / "bin" / "python"

EVENT_TYPES = [
    "CHMOD",
    "CHOWN",
    "READ",
    "WRITE",
    "UNLINK",
    "FILE_CREATE",
    "EXEC",
    "RENAME",
    "NETWORK",
    "MKDIR",
    "RMDIR",
]
RULES_PER_EVENT = 10
YES_MATCH_PATH_PREFIX = "/tmp/profiling_work"
YES_MATCH_RULE_ID = len(EVENT_TYPES) * RULES_PER_EVENT + 1


def main():
    _generate_no_match()
    _generate_yes_match()


def _generate_no_match():
    NO_MATCH_RULES_DIR.mkdir(parents=True, exist_ok=True)
    rule_id = 1
    for event_type in EVENT_TYPES:
        for index in range(1, RULES_PER_EVENT + 1):
            path = NO_MATCH_RULES_DIR / f"{event_type.lower()}_{index:02d}.yml"
            path.write_text(_no_match_rule(rule_id, event_type), encoding="utf-8")
            rule_id += 1
    _compile(NO_MATCH_RULES_DIR, BASE_CONFIG, NO_MATCH_OUTPUT)


def _generate_yes_match():
    """Compile the no-match rules plus the matching rule, using no_rule_matches_config.json's
    own features/userspace/kernel settings as the base, so the two configs only differ by the
    one extra rule, even if Rules/RulesGenerator/base_config.json has since drifted."""
    YES_MATCH_RULES_DIR.mkdir(parents=True, exist_ok=True)
    path = YES_MATCH_RULES_DIR / "path_match.yml"
    path.write_text(_yes_match_rule(), encoding="utf-8")
    with tempfile.TemporaryDirectory() as workdir:
        workdir = Path(workdir)
        rules_dir = workdir / "rules"
        rules_dir.mkdir()
        for rule_file in NO_MATCH_RULES_DIR.glob("*.yml"):
            shutil.copy(rule_file, rules_dir / rule_file.name)
        shutil.copy(path, rules_dir / path.name)
        base_config = workdir / "base_config.json"
        base_config.write_text(json.dumps(_base_from_existing_config(NO_MATCH_OUTPUT)), encoding="utf-8")
        _compile(rules_dir, base_config, YES_MATCH_OUTPUT)


def _base_from_existing_config(config_path):
    existing = json.loads(config_path.read_text(encoding="utf-8"))
    return {key: value for key, value in existing.items() if key != "rules"}


def _compile(rules_dir, base_config, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    python = VENV_PYTHON if VENV_PYTHON.is_file() else Path(sys.executable)
    subprocess.run(
        [
            str(python),
            str(GENERATOR_DIR / "create_config.py"),
            "-d", str(rules_dir),
            "-c", str(base_config),
            "-o", str(output),
        ],
        check=True,
    )
    print(f"wrote {output}")


def _no_match_rule(rule_id, event_type):
    return (
        f"id: {rule_id}\n"
        "description: uid is not 1337\n"
        "action: ALLOW_EVENT\n"
        "events:\n"
        f"  - {event_type}\n"
        "detection:\n"
        "  selection:\n"
        "    process.ruid|neq: 1337\n"
        "  condition: selection\n"
    )


def _yes_match_rule():
    return (
        f"id: {YES_MATCH_RULE_ID}\n"
        f"description: target file path starts with {YES_MATCH_PATH_PREFIX}\n"
        "action: ALLOW_EVENT\n"
        "events:\n"
        "  - FILE_CREATE\n"
        "  - CHMOD\n"
        "  - CHOWN\n"
        "detection:\n"
        "  selection:\n"
        f"    target.file.path|startswith: \"{YES_MATCH_PATH_PREFIX}\"\n"
        "  condition: selection\n"
    )


if __name__ == "__main__":
    main()
