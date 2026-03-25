Create owLSM config with rules.

## setup
```bash
# from the root directory 
# start the docker
docker build -t owlsm-ci-ubuntu20 .
docker run -it --rm -v "$PWD":/workspace -w /workspace owlsm-ci-ubuntu20 bash

# create a venv and install the requirements
cd Rules/RulesGenerator
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt
```

### Usage
The config file controls many aspects of owLSM.   
[base_config.json](./RulesGenerator/base_config.json) is an example of a configuration without any rules.  
[RuleExamples](./Rules/RuleExamples) is an example directory of rules. `create_config.py` searches for all the yaml files in this directory recursively 

```bash
# create a config file with rules
# the output_config is the complete config. Its your base config + rules.
python create_config.py -d <rules directory> -c <input config> -o <output_config>

# Real example 
python create_config.py -d ../RuleExamples -c base_config.json -o full_config.json
```

Now you can run owLSM with the generated config. Do it outside the docker  
```bash 
sudo /path/to/owlsm -c /path/to/full_config.json
```

> **Important:** Every time you add, remove, or modify Sigma rules, you must regenerate the full config file by re-running `create_config.py`. You cannot append or edit rules directly in the generated config — it must be rebuilt from your rule files each time.

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
