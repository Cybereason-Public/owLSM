Create owLSM config with rules.

## Versions

The Rules Generator comes in two forms:

- **Binary** — shipped in official releases. Path in release package: `owlsm/bin/rules_generator`
- **Python source** — available in the repository for development and testing. Path: `Rules/RulesGenerator/create_config.py`

### Using the binary

```bash
rules_generator -d <rules dir> -c <base config> -o <output config>
```

### Using the Python source

```bash
# From the repo root directory, start Docker
docker pull ghcr.io/cybereason-public/owlsm-ci:latest
docker run -it --rm -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash

# Set up the environment
cd Rules/RulesGenerator
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt

python create_config.py -d <rules dir> -c base_config.json -o <output config>
```

The rest of this document shows examples using the `rules_generator` binary. For Python source usage, replace `rules_generator` with `python create_config.py`.

---

## Usage

[base_config.json](./RulesGenerator/base_config.json) is an example configuration without rules.  
[RuleExamples](./RuleExamples) is an example directory of rules. The generator searches for all YAML files recursively. (This directory contains different types of rules)

```bash
# Create a config file with rules
# output_config is the complete config: your base config merged with compiled rules
rules_generator -d <rules directory> -c <input config> -o <output_config>

# Real example (from repo root)
rules_generator -d Rules/RuleExamples -c Rules/RulesGenerator/base_config.json -o full_config.json
```

Now you can run owLSM with the generated config. Do it outside the docker
```bash
sudo /path/to/owlsm -c /path/to/full_config.json
```

> **Important:** Every time you add, remove, or modify Sigma rules, you must regenerate the config by re-running the rules generator. You cannot append or edit rules directly in the generated config — it must be rebuilt from your rule files each time.

> **Note:** All rules generator log output is written to stderr (Errors, Info, ...).

#### Field mapping

If your Sigma rules use non-owLSM field names, pass a mapping file so the rules generator translates your field names to owLSM field names. See **[field mapping](https://cybereason-public.github.io/owLSM/rules/#field-mapping)** in the docs.

```bash
rules_generator -d Rules/RuleExamples -c Rules/RulesGenerator/base_config.json -o full_config.json -m field_mapping.yml
```

#### Placeholder expansion

Rules can use the `|expand` modifier with `%placeholders%` resolved from a YAML definitions file at build time. See **[placeholder expansion](https://cybereason-public.github.io/owLSM/rules/#placeholder-modifier)** in the docs.

```bash
rules_generator -d Rules/RuleExamples -c Rules/RulesGenerator/base_config.json -o full_config.json -p placeholders.yml
```

#### Memory mode (`--memory`)

Reads a JSON payload from stdin and writes the full config JSON to stdout. Use this when you don't want rule files or config files touching the disk.  
This is a niche option, irrelevant for 99% of users.

Cannot be used with any file-based flags (`-d`, `-c`, `-o`, `-p`, `-m`).

Input JSON schema: `Rules/RulesGenerator/memory_json_schema.json`.  
The output is the same full config JSON that file mode writes to the disk.

```bash
rules_generator --memory
```

## Rule Format

Rules are written in YAML format based on Sigma syntax. See `RuleExamples/` for examples.

### Required Fields
- `id`: Unique integer identifier
- `action`: One of `BLOCK_EVENT`, `ALLOW_EVENT`, `KILL_PROCESS`, etc.
- `events`: List of event types (CHMOD, READ, WRITE, EXEC, etc.)
- `detection`: Detection logic with selections and condition

Other Sigma fields like `title`, `severity`, `description`, etc. are optional.

## Running Tests

Unit tests for the rules generator (run from `Rules/RulesGenerator/` with the venv active):

```bash
# Run all tests
python -m pytest Tests/ -v

# Run specific test file
python -m pytest Tests/test_sigma_loader.py -v

# Run specific test class
python -m pytest Tests/test_sigma_loader.py::TestParseFieldKey -v

# Run with coverage (requires pytest-cov)
python -m pytest Tests/ -v --cov=RulesGenerator
```
