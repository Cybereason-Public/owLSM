#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

from junitparser import JUnitXml


def find_xml_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.xml"))


def parse_junit_xml_files(xml_files: list[Path]) -> dict:
    passed_tests = []
    failed_tests = []
    skipped_tests = []
    
    for xml_file in xml_files:
        try:
            junit_xml = JUnitXml.fromfile(str(xml_file))
            
            for suite in junit_xml:
                hostname = suite.hostname or xml_file.stem
                
                for case in suite:
                    test_name = case.name
                    
                    if case.is_passed:
                        passed_tests.append({
                            "test_name": test_name,
                            "hostname": hostname,
                        })
                    elif case.is_skipped:
                        skipped_tests.append({
                            "test_name": test_name,
                            "hostname": hostname,
                            "full_details": _get_result_details(case.result),
                        })
                    else:
                        # Both failures and errors go here
                        failed_tests.append({
                            "test_name": test_name,
                            "hostname": hostname,
                            "full_details": _get_result_details(case.result),
                        })
                            
        except Exception as e:
            failed_tests.append({
                "test_name": f"[PARSE ERROR] {xml_file.name}",
                "hostname": "aggregator",
                "full_details": str(e),
            })
    
    return {
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "skipped_tests": skipped_tests,
    }


def _get_result_details(results) -> str:
    if not results:
        return ""
    
    all_parts = []
    for result in results:
        parts = []
        
        if hasattr(result, "message") and result.message:
            parts.append(f"Message: {result.message}")
        
        if hasattr(result, "text") and result.text:
            parts.append(result.text)
        
        if parts:
            all_parts.append("\n".join(parts))
    
    return "\n\n".join(all_parts) if all_parts else ""


def build_aggregated_result(
    expected_count: int,
    actual_count: int,
    parsed_results: dict
) -> dict:
    """Build the final aggregated result dictionary."""
    passed = parsed_results["passed_tests"]
    failed = parsed_results["failed_tests"]
    skipped = parsed_results["skipped_tests"]
    
    return {
        "expected_number_of_results": expected_count,
        "actual_number_of_results": actual_count,
        "total_number_of_tests": len(passed) + len(failed) + len(skipped),
        "total_number_of_passed_tests": len(passed),
        "total_number_of_failed_tests": len(failed),
        "total_number_of_skipped_tests": len(skipped),
        "passed_tests": passed,
        "failed_tests": failed,
        "skipped_tests": skipped,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate multiple JUnit XML result files into a single JSON file."
    )
    parser.add_argument(
        "results_directory",
        type=Path,
        help="Directory containing JUnit XML result files"
    )
    parser.add_argument(
        "expected_file_count",
        type=int,
        help="Expected number of result files (number of runners)"
    )
    parser.add_argument(
        "output_file",
        type=Path,
        help="Path for the aggregated output JSON file"
    )
    
    args = parser.parse_args()
    
    if not args.results_directory.is_dir():
        print(f"Error: '{args.results_directory}' is not a directory", file=sys.stderr)
        sys.exit(1)
    
    xml_files = find_xml_files(args.results_directory)
    actual_count = len(xml_files)
    
    if actual_count == 0:
        print(f"Error: No XML files found in '{args.results_directory}'", file=sys.stderr)
        sys.exit(1)
    
    parsed_results = parse_junit_xml_files(xml_files)
    result = build_aggregated_result(args.expected_file_count, actual_count, parsed_results)
    
    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    
    print(f"\nAggregated results written to: {args.output_file}", file=sys.stderr)
    
    if args.expected_file_count != actual_count:
        sys.exit(2)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
