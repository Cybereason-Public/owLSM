Create owLSM config with rules.

## setup
```bash
# from the root directory 
# start the docker
docker build -t owlsm-ci-ubuntu18 .
docker run -it --rm -v "$PWD":/workspace -w /workspace owlsm-ci-ubuntu18 bash

# create a venv and install the requirements
cd Rules/RulesGenerator
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt
```

### Usage
The config file controls many aspects of owLSM. 
Check [base_config.json](./RulesGenerator/base_config.json) to see config example without any rules. 

```bash
# create a config file with rules
python create_config.py -d <rules directory> -c <input config> -o <output_config>

# Real example 
python create_config.py -d ../RuleExamples -c base_config.json -o full_config.json
```

## Rule Format
Rules are written in YAML format based on Sigma syntax. See `RuleExamples/` for examples.

### Required Fields
- `id`: Unique integer identifier
- `description`: Human-readable description
- `action`: One of `BLOCK_EVENT`, `ALLOW_EVENT`, `KILL_PROCESS`, etc.
- `events`: List of event types (CHMOD, READ, WRITE, EXEC, etc.)
- `detection`: Detection logic with selections and condition

## Running Tests
Unit tests for the rules generator

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
