#!/usr/bin/env python3
import argparse
import json
import sys
import subprocess
from pathlib import Path
import jsonschema


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Generate OWLSM configuration file from Sigma rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d /path/to/rules/directory -c base_config.json -o output_config.json
  %(prog)s -d ./sigma_rules -c config.json -o final.json -p placeholders.yml
        """
    )
    
    parser.add_argument(
        '-d', '--rules_directory',
        required=True,
        help='Directory containing Sigma rule files (.yml)'
    )
    
    parser.add_argument(
        '-c', '--config_file',
        required=True,
        help='Path to base configuration file (JSON)'
    )
    
    parser.add_argument(
        '-o', '--output_file',
        required=True,
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
        help='YAML file mapping external field names to owLSM field names (passed to main.py)'
    )

    return parser.parse_args()


def generate_rules_json(rules_directory, output_path, placeholder_file=None, mapping_file=None):
    print(f"Generating rules from directory: {rules_directory}")
    script_dir = Path(__file__).parent
    main_py = script_dir / 'main.py'
    
    if not main_py.exists():
        raise FileNotFoundError(f"main.py not found at {main_py}")

    cmd = [sys.executable, str(main_py), rules_directory, output_path]
    if placeholder_file:
        cmd.extend(['-p', placeholder_file])
    if mapping_file:
        cmd.extend(['-m', mapping_file])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True)
        
        if result.stderr:
            print(result.stderr, end='')
        
        print(f"✓ Rules generated successfully: {output_path}")
        return output_path
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error running main.py:", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        raise RuntimeError(f"Failed to generate rules: {e}")


def load_json_file(file_path):
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r') as f:
        return json.load(f)


def merge_config(base_config, rules_data):
    merged = dict(base_config)
    merged['rules'] = rules_data
    
    print(f"✓ Merged configuration:")
    print(f"  - {len(rules_data.get('id_to_string', {}))} strings")
    print(f"  - {len(rules_data.get('id_to_predicate', {}))} predicates")
    print(f"  - {len(rules_data.get('rules', []))} rules")
    
    return merged


def validate_config(config, schema):
    print("Validating configuration against schema...")
    try:
        jsonschema.validate(instance=config, schema=schema)
        print("✓ Configuration is valid")
    except jsonschema.ValidationError as e:
        print(f"✗ Validation error:", file=sys.stderr)
        print(f"  Message: {e.message}", file=sys.stderr)
        print(f"  Path: {' -> '.join(str(p) for p in e.path)}", file=sys.stderr)
        raise


def write_json_file(data, file_path, indent=2):
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=indent)
        f.write('\n')


def main():
    args = parse_arguments()
    
    try:
        print("=" * 70)
        print("Step 1: Generating rules.json from Sigma rules")
        print("=" * 70)
        
        rules_json_path = Path(args.rules_directory).parent / 'rules.json'
        generate_rules_json(
            args.rules_directory,
            str(rules_json_path),
            args.placeholders,
            args.mapping_file,
        )
        print()
        
        print("=" * 70)
        print("Step 2: Loading configuration files")
        print("=" * 70)
        
        print(f"Loading base config: {args.config_file}")
        base_config = load_json_file(args.config_file)
        print("✓ Base config loaded")
        
        print(f"Loading rules: {rules_json_path}")
        rules_data = load_json_file(rules_json_path)
        print("✓ Rules loaded")
        print()
        
        print("=" * 70)
        print("Step 3: Merging configuration")
        print("=" * 70)
        
        merged_config = merge_config(base_config, rules_data)
        print()
        
        print("=" * 70)
        print("Step 4: Validating configuration")
        print("=" * 70)
        
        script_dir = Path(__file__).parent
        schema_path = script_dir / '../../src/Userspace/configuration/schema.json'
        schema_path = schema_path.resolve()
        
        if not schema_path.exists():
            print(f"Warning: Schema not found at {schema_path}", file=sys.stderr)
            print("Skipping validation", file=sys.stderr)
        else:
            print(f"Loading schema: {schema_path}")
            schema = load_json_file(schema_path)
            validate_config(merged_config, schema)
        print()
        
        print("=" * 70)
        print("Step 5: Writing output")
        print("=" * 70)
        
        print(f"Writing to: {args.output_file}")
        write_json_file(merged_config, args.output_file)
        print(f"✓ Configuration written successfully")
        print()
        
        print("=" * 70)
        print("✓ Done! Configuration generated successfully")
        print("=" * 70)
        
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
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

