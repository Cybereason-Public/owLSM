#!/usr/bin/env python3
import argparse
import sys
from sigma_rule_loader import load_sigma_rules
from field_mapping import load_field_mapping_file
from AST import parse_rules
from postfix import convert_to_postfix
from serializer import write_json_file, to_json_string
from placeholder_expander import load_placeholders


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Convert Sigma YAML rules to JSON format for owLSM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s rules_directory
  %(prog)s rules_directory output.json
  %(prog)s rules_directory output.json -p placeholders.yml
        """
    )

    parser.add_argument(
        'rules_directory',
        help='Directory containing .yml sigma rules'
    )

    parser.add_argument(
        'output_file',
        nargs='?',
        default=None,
        help='Output JSON file (default: print to stdout)'
    )

    parser.add_argument(
        '-p', '--placeholders',
        default=None,
        help='YAML file with placeholder values for the |expand modifier'
    )

    parser.add_argument(
        '-m', '--mapping-file',
        default=None,
        help='YAML file mapping external field names to owLSM field names (source: destination)'
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    try:
        placeholders = None
        if args.placeholders:
            print(f"Loading placeholders from: {args.placeholders}", file=sys.stderr)
            placeholders = load_placeholders(args.placeholders)
            print(f"  Loaded {len(placeholders)} placeholder definitions", file=sys.stderr)

        field_mapping = None
        if args.mapping_file:
            print(f"Loading field mapping from: {args.mapping_file}", file=sys.stderr)
            field_mapping = load_field_mapping_file(args.mapping_file)
            print(f"  Loaded {len(field_mapping)} field alias(es)", file=sys.stderr)

        print("Step 1-2: Loading and validating rules...", file=sys.stderr)
        rules = load_sigma_rules(
            args.rules_directory,
            placeholders=placeholders,
            placeholder_file=args.placeholders,
            field_mapping=field_mapping,
        )
        print(f"  Loaded {len(rules)} rules", file=sys.stderr)

        print("Step 3: Parsing detection sections (AST)...", file=sys.stderr)
        ast_ctx = parse_rules(rules)
        print(f"  Built tables: {len(ast_ctx.id_to_string)} strings, {len(ast_ctx.id_to_predicate)} predicates", file=sys.stderr)

        print("Step 4: Converting to postfix notation...", file=sys.stderr)
        postfix_ctx = convert_to_postfix(ast_ctx)
        total_tokens = sum(len(r.tokens) for r in postfix_ctx.rules)
        print(f"  Generated {total_tokens} total tokens across {len(postfix_ctx.rules)} rules", file=sys.stderr)

        print("Step 5: Serializing to JSON...", file=sys.stderr)
        if args.output_file:
            write_json_file(postfix_ctx, args.output_file)
            print(f"  Written to: {args.output_file}", file=sys.stderr)
        else:
            json_str = to_json_string(postfix_ctx)
            print(json_str)

        print("Done!", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
