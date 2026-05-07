#!/usr/bin/env python3
import argparse
import json
import sys
import traceback
from pathlib import Path
import jsonschema
from AST import parse_rules
from field_mapping import load_field_mapping_file
from memory_input_handler import MemoryInputHandler
from placeholder_expander import load_placeholders
from postfix import convert_to_postfix, log_info
from serializer import serialize_context
from sigma_rule_loader import load_sigma_rules


def _resolve_first_existing_path(candidates):
    for candidate in candidates:
        resolved = Path(candidate).resolve()
        if resolved.exists():
            return resolved
    return None


def _packaged_and_embedded_candidates(relative_path):
    if hasattr(sys, "_MEIPASS"):
        meipass_dir = Path(getattr(sys, "_MEIPASS")).resolve()
        return [(meipass_dir / relative_path).resolve()]
    return []


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Generate OWLSM configuration file from Sigma rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d /path/to/rules/directory -c base_config.json -o output_config.json
  %(prog)s -d ./sigma_rules -c config.json -o final.json -p placeholders.yml
  %(prog)s --memory < input.json > output.json
        """
    )
    
    parser.add_argument(
        '-d', '--rules_directory',
        required=False,
        help='Directory containing Sigma rule files (.yml)'
    )
    
    parser.add_argument(
        '-c', '--config_file',
        required=False,
        help='Path to base configuration file (JSON)'
    )
    
    parser.add_argument(
        '-o', '--output_file',
        required=False,
        help='Path to output configuration file (JSON)'
    )

    parser.add_argument(
        '-p', '--placeholders',
        default=None,
        help='YAML file with placeholder values for the |expand modifier'
    )

    parser.add_argument(
        '-m', '--mapping-file',
        default=None,
        help='YAML file mapping external field names to owLSM field names'
    )

    parser.add_argument(
        '--memory',
        action='store_true',
        help='Read input JSON from stdin and write final config JSON to stdout. For users that dont want their rules/config files to be on the disk.'
    )

    args = parser.parse_args()

    if args.memory:
        file_mode_flags = [
            args.rules_directory,
            args.config_file,
            args.output_file,
            args.placeholders,
            args.mapping_file,
        ]
        if any(value is not None for value in file_mode_flags):
            parser.error("--memory cannot be used with file-based flags (-d/-c/-o/-p/-m)")
    else:
        if not args.rules_directory or not args.config_file or not args.output_file:
            parser.error("file mode requires -d/--rules_directory, -c/--config_file, and -o/--output_file")

    return args


def _build_rules_json(rules):
    log_info(f"Loaded and validated {len(rules)} rules")

    ast_ctx = parse_rules(rules)
    log_info(f"Parsed detection sections: {len(ast_ctx.id_to_string)} strings, {len(ast_ctx.id_to_predicate)} predicates")

    postfix_ctx = convert_to_postfix(ast_ctx)
    total_tokens = sum(len(rule.tokens) for rule in postfix_ctx.rules)
    log_info(f"Converted to postfix notation: {total_tokens} tokens across {len(postfix_ctx.rules)} rules")

    rules_data = serialize_context(postfix_ctx)
    log_info("Rules generated successfully")
    return rules_data


def generate_rules_json(rules_directory, placeholder_file=None, mapping_file=None):
    log_info(f"Generating rules from directory: {rules_directory}")
    try:
        placeholders = None
        if placeholder_file:
            log_info(f"Loading placeholders from: {placeholder_file}")
            placeholders = load_placeholders(placeholder_file)
            log_info(f"Loaded {len(placeholders)} placeholder definitions")

        field_mapping = None
        if mapping_file:
            log_info(f"Loading field mapping from: {mapping_file}")
            field_mapping = load_field_mapping_file(mapping_file)
            log_info(f"Loaded {len(field_mapping)} field alias(es)")

        rules = load_sigma_rules(
            rules_directory,
            placeholders=placeholders,
            placeholder_file=placeholder_file,
            field_mapping=field_mapping,
        )
        return _build_rules_json(rules)

    except Exception as e:
        print(f"✗ Error generating rules: {e}", file=sys.stderr)
        raise RuntimeError(f"Failed to generate rules: {e}")


def generate_rules_json_from_memory(memory_input_handler: MemoryInputHandler):
    log_info("Generating rules from stdin memory payload")
    try:
        placeholders = memory_input_handler.get_placeholders()
        if placeholders is not None:
            log_info(f"Loaded {len(placeholders)} placeholder definitions from stdin")

        field_mapping = memory_input_handler.get_field_mapping()
        if field_mapping is not None:
            log_info(f"Loaded {len(field_mapping)} field alias(es) from stdin")

        rules = memory_input_handler.load_rules(
            placeholders=placeholders,
            field_mapping=field_mapping,
        )
        return _build_rules_json(rules)
    except Exception as e:
        print(f"✗ Error generating rules from memory input: {e}", file=sys.stderr)
        raise RuntimeError(f"Failed to generate rules from memory input: {e}")


def load_json_file(file_path):
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def merge_config(base_config, rules_data):
    merged = dict(base_config)
    merged['rules'] = rules_data
    
    log_info(
        "Merged configuration: "
        f"{len(rules_data.get('id_to_string', {}))} strings, "
        f"{len(rules_data.get('id_to_predicate', {}))} predicates, "
        f"{len(rules_data.get('rules', []))} rules",
    )
    
    return merged


def validate_config(config, schema):
    log_info("Validating configuration against schema...")
    try:
        jsonschema.validate(instance=config, schema=schema)
        log_info("Configuration is valid")
    except jsonschema.ValidationError as e:
        print(f"✗ Validation error:", file=sys.stderr)
        print(f"  Message: {e.message}", file=sys.stderr)
        print(f"  Path: {' -> '.join(str(p) for p in e.path)}", file=sys.stderr)
        raise


def write_json_file(data, file_path, indent=2):
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent)
        f.write('\n')


def write_json_stdout(data, indent=2):
    json.dump(data, sys.stdout, indent=indent)
    sys.stdout.write('\n')


def get_embedded_base_config_path():
    script_dir = Path(__file__).resolve().parent
    candidates = [script_dir / "base_config.json", *_packaged_and_embedded_candidates("base_config.json")]
    resolved_path = _resolve_first_existing_path(candidates)
    if resolved_path is not None:
        return resolved_path

    candidate_text = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"base_config.json not found in expected paths: {candidate_text}")


def get_configuration_schema_path():
    script_dir = Path(__file__).resolve().parent
    candidates = [
        (script_dir / "../../src/Userspace/configuration/schema.json").resolve(),
        *_packaged_and_embedded_candidates("schema.json"),
    ]
    resolved_path = _resolve_first_existing_path(candidates)
    if resolved_path is not None:
        return resolved_path

    candidate_text = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"schema.json not found in expected paths: {candidate_text}")


def main():
    args = parse_arguments()
    
    try:
        log_info("Step 1/5: Generating rules data from Sigma rules")

        if args.memory:
            memory_input_handler = MemoryInputHandler.from_stdin()
            rules_data = generate_rules_json_from_memory(memory_input_handler)
            base_config_path = get_embedded_base_config_path()
        else:
            rules_data = generate_rules_json(
                args.rules_directory,
                args.placeholders,
                args.mapping_file,
            )
            base_config_path = args.config_file
            
        log_info("Step 2/5: Loading configuration files")
        base_config = load_json_file(base_config_path)
        log_info("Base config loaded")

        log_info("Step 3/5: Merging configuration")
        merged_config = merge_config(base_config, rules_data)

        log_info("Step 4/5: Validating configuration")
        schema_path = get_configuration_schema_path()
        log_info(f"Loading schema: {schema_path}")
        schema = load_json_file(schema_path)
        validate_config(merged_config, schema)

        log_info("Step 5/5: Writing output")
        if args.memory:
            log_info("Writing final config to stdout")
            write_json_stdout(merged_config)
        else:
            log_info(f"Writing to: {args.output_file}")
            write_json_file(merged_config, args.output_file)
        log_info("Configuration written successfully")
        log_info("Done. Configuration generated successfully")
        
    except FileNotFoundError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ JSON parsing error: {e}", file=sys.stderr)
        sys.exit(1)
    except jsonschema.ValidationError:
        print(f"✗ Configuration validation failed", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

