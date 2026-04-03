# AGENTS.md - Rules Generator

## Overview

The Rules Generator is a Python tool that converts Sigma-like security rules (written in YAML) into JSON format consumable by the owLSM userspace code. It parses rule detection logic, validates syntax, and serializes rules into a structured JSON output.
It does it by first parsing and validating the sigma rule, then converting it to an AST and then to prefix.
It maintains tables to track strings, predicates, ip addresses, etc.

The generator supports complex boolean expressions in detection logic, field comparisons (exact match, contains, starts_with, ends_with, regex), and multiple event types (CHMOD, READ, WRITE, EXEC, FORK, etc.).

---

## Project Structure
Modify this if changes.

```
RulesGenerator/
├── AGENTS.md              # This file
├── main.py                # CLI entry point - converts rules directory to JSON
├── sigma_rule_loader.py   # YAML parser and rule loader
├── AST.py                 # Abstract Syntax Tree for detection logic
├── postfix.py             # Infix to postfix expression conversion
├── serializer.py          # JSON serialization
├── regex_dfa.py           # Regex validation — converts regex to DFA and checks state limits
├── constants.py           # Shared constants (must match src/Shared/constants.h)
├── create_config.py       # Tool to create/update config files with new rules
├── requirements.txt       # Python dependencies
└── Tests/                 # pytest unit tests
    ├── test_sigma_loader.py
    ├── test_AST.py
    ├── test_regex_dfa.py
    └── ...
```

---

## Usage

### Setup (in Docker container)

```bash
cd Rules/RulesGenerator
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt
```

### Generate Rules JSON

```bash
# Output to stdout
python main.py ../RuleExamples

# Output to file
python main.py ../RuleExamples rules.json
```

### Create Config with New Rules

```bash
python create_config.py --help
python create_config.py <rules_dir> <output_config.json> # specify the current config.json file to just update its rules.
```

---



---

## Important Notes

- See how to run tests in `Rules/README.md`
- Constants in `constants.py` must stay in sync with `src/Shared/constants.h`
- Rule field names must match enums in `src/Shared/constants.h`
- See `Rules/README.md` for rule format documentation
- For rule examples see: `../RuleExamples/`, `./Tests/valid_rules`

