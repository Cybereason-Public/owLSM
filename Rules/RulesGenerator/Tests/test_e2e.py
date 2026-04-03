"""E2E tests for the Rules Generator.

These tests validate the complete pipeline from YAML rule files to parsed output.
Each test creates temporary YAML files and validates expected behavior.
"""
import json
import pytest
from sigma_rule_loader import load_sigma_rules, SigmaRule
from AST import parse_rules
from postfix import convert_to_postfix
from serializer import serialize_context, to_json_string
from constants import StringType


# =============================================================================
# 1) ID Validation Tests
# =============================================================================

class TestIdValidation:
    """E2E tests for rule ID validation."""

    def test_negative_id_raises(self, tmp_path):
        """Negative ID should raise an exception."""
        rule = """
id: -1
description: "Rule with negative ID"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_non_integer_id_raises(self, tmp_path):
        """Non-integer ID (string) should raise an exception."""
        rule = """
id: "not_an_integer"
description: "Rule with string ID"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_no_id_raises(self, tmp_path):
        """Missing ID field should raise an exception."""
        rule = """
description: "Rule without ID"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_two_ids_last_wins(self, tmp_path):
        """Two ID fields in same rule - YAML behavior: last ID wins, no exception."""
        rule = """
id: 100
description: "Rule with two IDs"
action: "BLOCK_EVENT"
id: 200
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].id == 200  # Last ID wins


# =============================================================================
# 2) Action Validation Tests
# =============================================================================

class TestActionValidation:
    """E2E tests for rule action validation."""

    def test_no_action_raises(self, tmp_path):
        """Missing action field should raise an exception."""
        rule = """
id: 1
description: "Rule without action"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_two_actions_last_wins(self, tmp_path):
        """Two action fields in same rule - YAML behavior: last action wins, no exception."""
        rule = """
id: 1
description: "Rule with two actions"
action: "BLOCK_EVENT"
events: [CHMOD]
action: "KILL_PROCESS"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].action == "KILL_PROCESS"  # Last action wins


# =============================================================================
# 3) Events Validation Tests
# =============================================================================

class TestEventsValidation:
    """E2E tests for rule events validation."""

    def test_invalid_event_raises(self, tmp_path):
        """Invalid event type should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid event"
action: "BLOCK_EVENT"
events: [INVALID_EVENT]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_no_events_raises(self, tmp_path):
        """Missing events field should raise an exception."""
        rule = """
id: 1
description: "Rule without events"
action: "BLOCK_EVENT"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_empty_events_raises(self, tmp_path):
        rule = """
id: 1
description: "Rule without events"
action: "BLOCK_EVENT"
events: []
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_duplicate_event_types_raises(self, tmp_path):
        """Duplicate event types in same list should raise an exception."""
        rule = """
id: 1
description: "Rule with duplicate events"
action: "BLOCK_EVENT"
events: [CHMOD, CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_two_events_keys_last_wins(self, tmp_path):
        """Two events keys in same rule - YAML behavior: last events wins, no exception."""
        rule = """
id: 1
description: "Rule with two events keys"
action: "BLOCK_EVENT"
events: [CHMOD]
events: [READ, WRITE]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert set(rules[0].events) == {"READ", "WRITE"}  # Last events wins

    def test_event_case_insensitivity(self, tmp_path):
        """Event types should be case insensitive - lowercase should work."""
        rule = """
id: 1
description: "Rule with lowercase events"
action: "BLOCK_EVENT"
events: [chmod, ReaD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        # Events should be normalized to uppercase
        assert set(rules[0].events) == {"CHMOD", "READ"}

    def test_duplicate_events_different_cases_raises(self, tmp_path):
        """Duplicate events with different cases should raise an exception."""
        rule = """
id: 1
description: "Rule with duplicate events different cases"
action: "BLOCK_EVENT"
events: [CHMOD, chmod]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)


# =============================================================================
# 4) Detection Validation Tests
# =============================================================================

class TestDetectionValidation:
    """E2E tests for rule detection validation."""

    def test_no_selections_raises(self, tmp_path):
        """Detection with no selections (only condition) should raise an exception."""
        rule = """
id: 1
description: "Rule with no selections"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    condition:
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_no_condition_raises(self, tmp_path):
        """Detection without condition should raise an exception."""
        rule = """
id: 1
description: "Rule without condition"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_unused_selection_no_raise(self, tmp_path):
        """Selection not used in condition should not raise - it's allowed."""
        rule = """
id: 1
description: "Rule with unused selection"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel_used:
        process.file.filename: "test.exe"
    sel_unused:
        process.cmd: "unused"
    condition: sel_used
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_duplicate_selection_names_last_wins(self, tmp_path):
        """Duplicate selection names - YAML behavior: last selection wins, no exception."""
        rule = """
id: 1
description: "Rule with duplicate selection names"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "first.exe"
    sel:
        process.file.filename: "second.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        # Verify that last selection value is used (second.exe)
        assert rules[0].detection["sel"]["process.file.filename"] == "second.exe"

    def test_different_names_same_values_no_raise(self, tmp_path):
        """Different selection names with identical values should not raise."""
        rule = """
id: 1
description: "Rule with different names but same values"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.file.filename: "same.exe"
    sel2:
        process.file.filename: "same.exe"
    condition: sel1 or sel2
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        # Verify both selections exist as separate entries
        assert "sel1" in rules[0].detection
        assert "sel2" in rules[0].detection
        assert rules[0].detection["sel1"] == rules[0].detection["sel2"]  # Same values


# =============================================================================
# 5) Selection Validation Tests
# =============================================================================

class TestSelectionValidation:
    """E2E tests for selection validation."""

    def test_empty_selection_raises(self, tmp_path):
        """Empty selection (no fields) should raise an exception."""
        rule = """
id: 1
description: "Rule with empty selection"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel: {}
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_invalid_field_key_raises(self, tmp_path):
        """Invalid field key (process.file.invalid) should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid field"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.invalid: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_key_without_value_raises(self, tmp_path):
        """Valid key with null/no value should raise an exception."""
        rule = """
id: 1
description: "Rule with key without value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename:
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_empty_string_value_raises(self, tmp_path):
        """Empty string value should raise an exception."""
        rule = """
id: 1
description: "Rule with empty string value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: ""
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_invalid_quantifier_raises(self, tmp_path):
        """Invalid quantifier (e.g., 'some') should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid quantifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|some: ["value1", "value2"]
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_multiple_quantifiers_raises(self, tmp_path):
        """Multiple quantifiers in same key should raise an exception."""
        rule = """
id: 1
description: "Rule with multiple quantifiers"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|all|all: ["value1", "value2"]
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_invalid_modifier_for_string_field_raises(self, tmp_path):
        """Invalid modifier for string field should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid string modifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|regex: "test.*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_invalid_modifier_for_numeric_field_raises(self, tmp_path):
        """Invalid modifier for numeric field should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid numeric modifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|invalid: 1000
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_invalid_modifier_for_enum_field_raises(self, tmp_path):
        """Invalid modifier for enum field should raise an exception."""
        rule = """
id: 1
description: "Rule with invalid enum modifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|invalid: "REGULAR_FILE"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_multiple_string_modifiers_raises(self, tmp_path):
        """Multiple string modifiers in same key should raise an exception."""
        rule = """
id: 1
description: "Rule with multiple string modifiers"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|contains|startswith: "test"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_multiple_numeric_modifiers_raises(self, tmp_path):
        """Multiple numeric modifiers in same key should raise an exception."""
        rule = """
id: 1
description: "Rule with multiple numeric modifiers"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|gt|lt: 1000
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_string_modifier_on_numeric_field_raises(self, tmp_path):
        """String modifier on numeric field should raise an exception."""
        rule = """
id: 1
description: "Rule with string modifier on numeric field"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|contains: 1000
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_numeric_modifier_on_string_field_raises(self, tmp_path):
        """Numeric modifier on string field should raise an exception."""
        rule = """
id: 1
description: "Rule with numeric modifier on string field"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|gt: "test"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_string_modifier_on_enum_field_raises(self, tmp_path):
        """String modifier on enum field should raise an exception."""
        rule = """
id: 1
description: "Rule with string modifier on enum field"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|contains: "REGULAR_FILE"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_mixed_string_and_numeric_modifiers_raises(self, tmp_path):
        """Numeric and string modifier in same key should raise an exception."""
        rule = """
id: 1
description: "Rule with mixed modifiers"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|contains|gt: "test"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_string_without_quotes_no_raise(self, tmp_path):
        """String value without quotation marks should work (valid YAML)."""
        rule = """
id: 1
description: "Rule with unquoted string"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: test.exe
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        # Verify the string is correctly parsed
        assert rules[0].detection["sel"]["process.file.filename"] == "test.exe"

    def test_suffix_wildcard_works(self, tmp_path):
        rule = """
id: 1
description: "Rule with suffix wildcard"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "testvalue*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        # Should have one rule with startswith predicate
        assert len(ctx.rules) == 1
        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "startswith"
        assert ctx.id_to_string[pred.string_idx].value == "testvalue"

    def test_prefix_wildcard_works(self, tmp_path):
        rule = """
id: 1
description: "Rule with prefix wildcard"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "*testvalue"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.rules) == 1
        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "endswith"
        assert ctx.id_to_string[pred.string_idx].value == "testvalue"

    def test_contains_wildcard_works(self, tmp_path):
        rule = """
id: 1
description: "Rule with both wildcards"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "*testvalue*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.rules) == 1
        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "contains"
        assert ctx.id_to_string[pred.string_idx].value == "testvalue"

    def test_internal_wildcard_works(self, tmp_path):
        rule = """
id: 1
description: "Rule with internal wildcard"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test*value"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.rules) == 1
        # Internal wildcard creates an AND expression
        expr = ctx.rules[0].condition_expr
        assert expr.operator_type == "AND"
        assert len(expr.children) == 2

    def test_wildcard_question_mark_raises(self, tmp_path):
        """String value with wildcard question mark should raise an exception."""
        from AST import parse_rules
        
        rule = """
id: 1
description: "Rule with wildcard question mark"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "testvalue?"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_lone_asterisk_raises(self, tmp_path):
        """A single asterisk (*) is not a valid pattern."""
        rule = """
id: 1
description: "Rule with lone asterisk"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="single '\\*'"):
            load_sigma_rules(str(tmp_path))

    def test_too_many_wildcards_raises(self, tmp_path):
        rule = """
id: 1
description: "Rule with too many wildcards"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "*test*val*ue*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="too many wildcards"):
            load_sigma_rules(str(tmp_path))

    def test_chmod_with_rename_fields_raises(self, tmp_path):
        """CHMOD event with RENAME-specific fields should raise an exception."""
        rule = """
id: 1
description: "Rule with chmod and rename fields"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        rename.source_file.path: "/etc/passwd"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)


# =============================================================================
# 6) Condition Validation Tests
# =============================================================================

class TestConditionValidation:
    """E2E tests for condition validation."""

    def test_empty_condition_raises(self, tmp_path):
        """Empty condition should raise an exception."""
        rule = """
id: 1
description: "Rule with empty condition"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: 
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_more_open_parens_raises(self, tmp_path):
        """More '(' than ')' should raise an exception."""
        rule = """
id: 1
description: "Rule with unbalanced parens"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.file.filename: "test1.exe"
    sel2:
        process.file.filename: "test2.exe"
    condition: ((sel1 and sel2)
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_more_close_parens_raises(self, tmp_path):
        """More ')' than '(' should raise an exception."""
        rule = """
id: 1
description: "Rule with unbalanced parens"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.file.filename: "test1.exe"
    sel2:
        process.file.filename: "test2.exe"
    condition: (sel1 and sel2))
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_condition_starts_with_and_raises(self, tmp_path):
        """Condition starting with 'and' should raise an exception."""
        rule = """
id: 1
description: "Rule with condition starting with and"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: and sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_condition_starts_with_or_raises(self, tmp_path):
        """Condition starting with 'or' should raise an exception."""
        rule = """
id: 1
description: "Rule with condition starting with or"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: or sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_condition_starts_with_not_no_raise(self, tmp_path):
        """Condition starting with 'not' is valid and should not raise."""
        rule = """
id: 1
description: "Rule with condition starting with not"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: not sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_condition_ends_with_and_raises(self, tmp_path):
        """Condition ending with 'and' should raise an exception."""
        rule = """
id: 1
description: "Rule with condition ending with and"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel and
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_condition_ends_with_or_raises(self, tmp_path):
        """Condition ending with 'or' should raise an exception."""
        rule = """
id: 1
description: "Rule with condition ending with or"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel or
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_condition_ends_with_not_raises(self, tmp_path):
        """Condition ending with 'not' should raise an exception."""
        rule = """
id: 1
description: "Rule with condition ending with not"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel not
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_no_operator_between_selections_raises(self, tmp_path):
        """Missing operator between selections should raise an exception."""
        rule = """
id: 1
description: "Rule without operator between selections"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.file.filename: "test1.exe"
    sel2:
        process.file.filename: "test2.exe"
    condition: sel1 sel2
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception):
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)

    def test_comprehensive_rule_all_fields_no_raise(self, tmp_path):
        """Comprehensive rule with all event types, fields, and modifiers should work."""
        rule = """
id: 1
description: "Comprehensive rule testing all fields and modifiers"
action: "BLOCK_EVENT"
events: [CHMOD, CHOWN, READ, WRITE, UNLINK, FILE_CREATE, EXEC, RENAME]
detection:
    process_fields:
        process.pid|gt: 100
        process.ppid|gte: 1
        process.ruid|lt: 65535
        process.rgid|lte: 65535
        process.euid: 0
        process.egid: 0
        process.suid: 0
        process.ptrace_flags: 0
        process.cmd|contains: "test"
        process.file.path|startswith: "/usr"
        process.file.filename|endswith: ".exe"
        process.file.owner.uid: 0
        process.file.owner.gid: 0
        process.file.mode: 755
        process.file.suid: 0
        process.file.sgid: 0
        process.file.nlink: 1
        process.file.type: "REGULAR_FILE"
    parent_fields:
        parent_process.pid: 1
        parent_process.cmd|contains: "init"
        parent_process.file.path|startswith: "/sbin"
        parent_process.file.filename: "init"
        parent_process.file.type: "REGULAR_FILE"
    condition: process_fields or parent_fields
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1
        assert ctx.rules[0].rule_id == 1


# =============================================================================
# 7) JSON Validation Tests
# =============================================================================

class TestJsonValidation:
    """E2E tests for full pipeline JSON output validation."""

    def test_all_different_strings_and_predicates(self, tmp_path):
        """5 rules, all different strings (3 per rule = 15), all different predicates (5 per rule = 25)."""
        from postfix import convert_to_postfix
        from serializer import serialize_context
        
        # Create 5 rules with unique strings and predicates
        for i in range(1, 6):
            rule = f"""
id: {i}
description: "Rule {i} with unique strings and predicates"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "unique_file_{i}.exe"
        process.cmd|contains: "unique_cmd_{i}"
        process.file.path|startswith: "/unique/path/{i}"
        process.pid|gt: {i * 100}
        process.euid: {i * 10}
    condition: sel
"""
            (tmp_path / f"rule_{i}.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        # Verify id_to_string has 15 entries (3 strings per rule * 5 rules)
        assert len(data["id_to_string"]) == 15
        
        # Verify id_to_predicate has 25 entries (5 predicates per rule * 5 rules)
        assert len(data["id_to_predicate"]) == 25
        
        # Verify string values are correct
        string_values = {entry["value"] for entry in data["id_to_string"].values()}
        for i in range(1, 6):
            assert f"unique_file_{i}.exe" in string_values
            assert f"unique_cmd_{i}" in string_values
            assert f"/unique/path/{i}" in string_values
        
        # Verify string_type flags
        for entry in data["id_to_string"].values():
            if "cmd" in entry["value"]:
                assert entry["string_type"] == StringType.CONTAINS.value
            else:
                assert entry["string_type"] == StringType.DEFAULT.value
        
        # Verify predicates have correct string_idx and numerical_value
        for pred in data["id_to_predicate"].values():
            if pred["field"] == "process.pid":
                assert pred["string_idx"] == -1  # Numeric pred has no string
                assert pred["numerical_value"] in [100, 200, 300, 400, 500]
            elif pred["field"] == "process.euid":
                assert pred["string_idx"] == -1
                assert pred["numerical_value"] in [10, 20, 30, 40, 50]
            else:
                assert pred["string_idx"] >= 0  # String pred has valid string_idx
                assert pred["numerical_value"] == -1
        
        # Verify rules have correct metadata
        assert len(data["rules"]) == 5
        for rule in data["rules"]:
            assert rule["id"] in [1, 2, 3, 4, 5]
            assert rule["action"] == "BLOCK_EVENT"
            assert rule["applied_events"] == ["CHMOD"]
            assert len(rule["tokens"]) > 0

    def test_same_strings_different_predicates(self, tmp_path):
        """5 rules, same 5 strings, but different predicates (different fields/modifiers)."""
        from postfix import convert_to_postfix
        from serializer import serialize_context
        
        # All rules use the same 5 string values, but each rule creates different predicates
        # by using different fields or different modifiers
        # Rule 1: exactmatch on process.file.filename
        # Rule 2: contains on process.file.filename (same string, different modifier = different pred)
        # Rule 3: exactmatch on process.cmd (same string, different field = different pred)
        # etc.
        
        shared_strings = ["shared1", "shared2", "shared3", "shared4", "shared5"]
        
        # Rule 1: All exactmatch on process.file.filename
        rule1 = f"""
id: 1
description: "Rule 1"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "{shared_strings[0]}"
        process.file.path: "{shared_strings[1]}"
        process.cmd: "{shared_strings[2]}"
        parent_process.file.filename: "{shared_strings[3]}"
        parent_process.cmd: "{shared_strings[4]}"
    condition: sel
"""
        (tmp_path / "rule_1.yml").write_text(rule1)
        
        # Rule 2: All contains modifier (same strings, different operation)
        rule2 = f"""
id: 2
description: "Rule 2"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|contains: "{shared_strings[0]}"
        process.file.path|contains: "{shared_strings[1]}"
        process.cmd|contains: "{shared_strings[2]}"
        parent_process.file.filename|contains: "{shared_strings[3]}"
        parent_process.cmd|contains: "{shared_strings[4]}"
    condition: sel
"""
        (tmp_path / "rule_2.yml").write_text(rule2)
        
        # Rule 3: All startswith modifier
        rule3 = f"""
id: 3
description: "Rule 3"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|startswith: "{shared_strings[0]}"
        process.file.path|startswith: "{shared_strings[1]}"
        process.cmd|startswith: "{shared_strings[2]}"
        parent_process.file.filename|startswith: "{shared_strings[3]}"
        parent_process.cmd|startswith: "{shared_strings[4]}"
    condition: sel
"""
        (tmp_path / "rule_3.yml").write_text(rule3)
        
        # Rule 4: All endswith modifier
        rule4 = f"""
id: 4
description: "Rule 4"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|endswith: "{shared_strings[0]}"
        process.file.path|endswith: "{shared_strings[1]}"
        process.cmd|endswith: "{shared_strings[2]}"
        parent_process.file.filename|endswith: "{shared_strings[3]}"
        parent_process.cmd|endswith: "{shared_strings[4]}"
    condition: sel
"""
        (tmp_path / "rule_4.yml").write_text(rule4)
        
        # Rule 5: Mixed - different fields than rule 1 (same strings, different fields)
        rule5 = f"""
id: 5
description: "Rule 5"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        parent_process.file.path: "{shared_strings[0]}"
        process.file.filename: "{shared_strings[1]}"
        parent_process.cmd: "{shared_strings[2]}"
        process.cmd: "{shared_strings[3]}"
        process.file.path: "{shared_strings[4]}"
    condition: sel
"""
        (tmp_path / "rule_5.yml").write_text(rule5)
        
        rules = load_sigma_rules(str(tmp_path))
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        # Verify id_to_string has only 5 entries (strings are deduplicated)
        assert len(data["id_to_string"]) == 5
        
        # Verify id_to_predicate has 25 entries (5 predicates per rule * 5 rules, all unique)
        # Each rule uses same strings but different field+operation combinations
        assert len(data["id_to_predicate"]) == 25
        
        # Verify all string values are present
        actual_values = {entry["value"] for entry in data["id_to_string"].values()}
        assert actual_values == set(shared_strings)
        
        # Verify string_type flags: all 5 entries are CONTAINS (upgraded because Rule 2 uses contains)
        for entry in data["id_to_string"].values():
            assert entry["string_type"] == StringType.CONTAINS.value
        
        # Verify all predicates are string predicates (no numeric)
        for pred in data["id_to_predicate"].values():
            assert pred["string_idx"] >= 0
            assert pred["numerical_value"] == -1
        
        # Verify rules
        assert len(data["rules"]) == 5

    def test_same_strings_same_predicates_different_conditions(self, tmp_path):
        """5 rules, same 5 strings, same 5 predicates, but different conditions."""
        from postfix import convert_to_postfix
        from serializer import serialize_context
        
        # All rules use exactly the same selections, only condition differs
        conditions = [
            "sel1 and sel2",
            "sel1 or sel2", 
            "sel1 and not sel2",
            "(sel1 or sel2) and sel3",
            "sel1 or (sel2 and sel3)"
        ]
        
        for i in range(1, 6):
            rule = f"""
id: {i}
description: "Rule {i} with different condition"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.file.filename: "same_file.exe"
        process.pid|gt: 100
    sel2:
        process.cmd|contains: "same_cmd"
    sel3:
        process.file.path|startswith: "/same/path"
    condition: {conditions[i-1]}
"""
            (tmp_path / f"rule_{i}.yml").write_text(rule)
        
        rules = load_sigma_rules(str(tmp_path))
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        # Verify id_to_string has only 3 entries (3 unique strings)
        assert len(data["id_to_string"]) == 3
        
        # Verify id_to_predicate has only 4 entries (4 unique predicates: 3 string + 1 numeric)
        assert len(data["id_to_predicate"]) == 4
        
        # Verify string values
        string_values = {entry["value"] for entry in data["id_to_string"].values()}
        assert string_values == {"same_file.exe", "same_cmd", "/same/path"}
        
        # Verify string_type flags
        for entry in data["id_to_string"].values():
            if entry["value"] == "same_cmd":
                assert entry["string_type"] == StringType.CONTAINS.value
            else:
                assert entry["string_type"] == StringType.DEFAULT.value
        
        # Verify numeric predicate
        numeric_preds = [p for p in data["id_to_predicate"].values() if p["numerical_value"] != -1]
        assert len(numeric_preds) == 1
        assert numeric_preds[0]["numerical_value"] == 100
        assert numeric_preds[0]["field"] == "process.pid"
        
        # Verify all 5 rules exist with different token sequences
        assert len(data["rules"]) == 5
        token_sequences = [tuple(t["operator_type"] for t in rule["tokens"]) for rule in data["rules"]]
        # All token sequences should be different (different conditions)
        assert len(set(token_sequences)) == 5
        
        # Verify rule metadata
        for rule in data["rules"]:
            assert rule["action"] == "BLOCK_EVENT"
            assert rule["applied_events"] == ["CHMOD"]
            assert "different condition" in rule["description"]


# =============================================================================
# 8) Extra Sigma Fields Ignored Tests
# =============================================================================

RULE_WITH_ALL_EXTRA_SIGMA_FIELDS = """
title: "Detect Suspicious chmod on /etc"
id: 5000
status: stable
description: "Detects suspicious chmod on sensitive paths"
author: "Test Author (Test Organization)"
date: 2024-01-15
modified: 2025-06-20
references:
    - https://attack.mitre.org/techniques/T1222/
    - https://example.com/advisory-123
tags:
    - attack.defense-evasion
    - attack.t1222.002
    - detection.threat-hunting
logsource:
    product: linux
    category: process_creation
    service: auditd
    definition: |
        Required auditd configuration:
        -a always,exit -F arch=b64 -S chmod -k chmod_monitor
related:
    - id: e3a8a052-111f-4606-9aee-f28ebeb76776
      type: derived
    - id: abcdef01-2345-6789-abcd-ef0123456789
      type: similar
falsepositives:
    - Legitimate administrative activity
    - Package installation scripts
level: high
simulation:
    - type: atomic-red-team
      name: chmod - Change file or folder mode
      technique: T1222.002
      atomic_guid: ffe2346c-abd5-4b45-a713-bf5f1ebd573a
action: "BLOCK_EVENT"
events:
    - CHMOD
detection:
    selection_path:
        target.file.path|startswith: "/etc/"
    selection_mode:
        chmod.requested_mode: 777
    condition: selection_path and selection_mode
"""

RULE_WITHOUT_EXTRA_SIGMA_FIELDS = """
id: 5000
description: "Detects suspicious chmod on sensitive paths"
action: "BLOCK_EVENT"
events:
    - CHMOD
detection:
    selection_path:
        target.file.path|startswith: "/etc/"
    selection_mode:
        chmod.requested_mode: 777
    condition: selection_path and selection_mode
"""


class TestExtraSigmaFieldsIgnored:
    """Tests that standard Sigma metadata fields (title, status, level, author,
    date, modified, references, tags, falsepositives, logsource, related,
    simulation) are silently ignored and do not affect rule loading, parsing,
    or serialization."""

    def test_rule_with_all_extra_fields_loads(self, tmp_path):
        """Rule containing all standard Sigma metadata fields should load without error."""
        (tmp_path / "rule.yml").write_text(RULE_WITH_ALL_EXTRA_SIGMA_FIELDS)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].id == 5000
        assert rules[0].description == "Detects suspicious chmod on sensitive paths"
        assert rules[0].action == "BLOCK_EVENT"
        assert rules[0].events == ["CHMOD"]

    def test_rule_with_all_extra_fields_parses(self, tmp_path):
        """Rule with extra Sigma fields should parse through the full pipeline."""
        (tmp_path / "rule.yml").write_text(RULE_WITH_ALL_EXTRA_SIGMA_FIELDS)

        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        assert len(ctx.rules) == 1
        assert ctx.rules[0].rule_id == 5000

    def test_extra_fields_not_in_sigma_rule_object(self, tmp_path):
        """Extra Sigma fields must not leak into the SigmaRule dataclass."""
        (tmp_path / "rule.yml").write_text(RULE_WITH_ALL_EXTRA_SIGMA_FIELDS)

        rules = load_sigma_rules(str(tmp_path))
        rule = rules[0]

        extra_field_names = [
            "title", "status", "level", "author", "date", "modified",
            "references", "tags", "logsource", "falsepositives", "related",
            "simulation",
        ]
        for field_name in extra_field_names:
            assert not hasattr(rule, field_name), (
                f"SigmaRule should not have attribute '{field_name}'"
            )

    def test_extra_fields_not_in_serialized_json(self, tmp_path):
        """Extra Sigma fields must not appear anywhere in the final JSON output."""
        (tmp_path / "rule.yml").write_text(RULE_WITH_ALL_EXTRA_SIGMA_FIELDS)

        rules = load_sigma_rules(str(tmp_path))
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)

        forbidden_keys = {
            "title", "status", "level", "author", "date", "modified",
            "references", "tags", "logsource", "falsepositives", "related",
            "simulation",
        }
        for rule_data in data["rules"]:
            rule_keys = set(rule_data.keys())
            leaked = rule_keys & forbidden_keys
            assert not leaked, f"Serialized rule contains unexpected keys: {leaked}"

    def test_extra_fields_produce_identical_output(self, tmp_path):
        """A rule with extra Sigma fields must produce the same JSON output
        as the identical rule without those fields."""
        dir_with = tmp_path / "with_extra"
        dir_without = tmp_path / "without_extra"
        dir_with.mkdir()
        dir_without.mkdir()

        (dir_with / "rule.yml").write_text(RULE_WITH_ALL_EXTRA_SIGMA_FIELDS)
        (dir_without / "rule.yml").write_text(RULE_WITHOUT_EXTRA_SIGMA_FIELDS)

        rules_with = load_sigma_rules(str(dir_with))
        parsed_with = parse_rules(rules_with)
        postfix_with = convert_to_postfix(parsed_with)
        data_with = serialize_context(postfix_with)

        rules_without = load_sigma_rules(str(dir_without))
        parsed_without = parse_rules(rules_without)
        postfix_without = convert_to_postfix(parsed_without)
        data_without = serialize_context(postfix_without)

        assert data_with == data_without

    def test_logsource_with_nested_definition_ignored(self, tmp_path):
        """logsource with nested sub-keys (product, category, service, definition)
        should be silently ignored."""
        rule = """
id: 5001
description: "Rule with complex logsource"
action: "BLOCK_EVENT"
events:
    - EXEC
logsource:
    product: linux
    category: process_creation
    service: auditd
    definition: |
        Required auditd configuration:
        -a always,exit -F arch=b64 -S execve -k exec_monitor
        -a always,exit -F arch=b32 -S execve -k exec_monitor
detection:
    sel:
        target.process.cmd|contains: "bash"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_tags_with_mitre_attack_ids_ignored(self, tmp_path):
        """tags with MITRE ATT&CK technique IDs should be silently ignored."""
        rule = """
id: 5002
description: "Rule with many MITRE tags"
action: "BLOCK_EVENT"
events:
    - CHMOD
tags:
    - attack.execution
    - attack.t1059
    - attack.t1059.004
    - attack.persistence
    - attack.t1543.002
    - attack.defense-evasion
    - detection.threat-hunting
detection:
    sel:
        process.file.filename: "chmod"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_simulation_with_atomic_red_team_ignored(self, tmp_path):
        """simulation block with Atomic Red Team entries should be silently ignored."""
        rule = """
id: 5003
description: "Rule with simulation block"
action: "KILL_PROCESS"
events:
    - WRITE
simulation:
    - type: atomic-red-team
      name: Pad Binary to Change Hash
      technique: T1027.001
      atomic_guid: ffe2346c-abd5-4b45-a713-bf5f1ebd573a
    - type: atomic-red-team
      name: Another Test
      technique: T1059.004
      atomic_guid: 12345678-1234-1234-1234-123456789012
detection:
    sel:
        target.file.path|startswith: "/etc/shadow"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].action == "KILL_PROCESS"

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_related_with_multiple_entries_ignored(self, tmp_path):
        """related block with derived/similar/obsolete entries should be silently ignored."""
        rule = """
id: 5004
description: "Rule with related entries"
action: "BLOCK_EVENT"
events:
    - READ
related:
    - id: e3a8a052-111f-4606-9aee-f28ebeb76776
      type: derived
    - id: abcdef01-2345-6789-abcd-ef0123456789
      type: similar
    - id: 99999999-9999-9999-9999-999999999999
      type: obsolete
detection:
    sel:
        target.file.path|contains: "/etc/passwd"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_multiple_rules_with_extra_fields(self, tmp_path):
        """Multiple rules each with different extra fields should all load and parse."""
        rule1 = """
id: 5010
title: "First Rule"
status: experimental
level: critical
author: "Author One"
description: "First rule with extras"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "badtool"
    condition: sel
"""
        rule2 = """
id: 5011
title: "Second Rule"
date: 2023-03-15
modified: 2024-12-01
tags:
    - attack.discovery
    - attack.t1082
references:
    - https://example.com/ref1
falsepositives:
    - System monitoring tools
description: "Second rule with extras"
action: "ALLOW_EVENT"
events: [READ]
detection:
    sel:
        target.file.path|startswith: "/proc/"
    condition: sel
"""
        rule3 = """
id: 5012
title: "Third Rule"
logsource:
    product: linux
    service: syslog
simulation:
    - type: atomic-red-team
      name: Test
      technique: T1070.002
      atomic_guid: aabbccdd-1122-3344-5566-778899aabbcc
related:
    - id: 12345678-abcd-ef01-2345-6789abcdef01
      type: derived
description: "Third rule with extras"
action: "BLOCK_KILL_PROCESS"
events: [EXEC]
detection:
    sel:
        target.process.cmd|contains: "rm -rf"
    condition: sel
"""
        (tmp_path / "rule1.yml").write_text(rule1)
        (tmp_path / "rule2.yml").write_text(rule2)
        (tmp_path / "rule3.yml").write_text(rule3)

        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 3

        parsed_ctx = parse_rules(rules)
        assert len(parsed_ctx.rules) == 3

        postfix_ctx = convert_to_postfix(parsed_ctx)
        data = serialize_context(postfix_ctx)
        assert len(data["rules"]) == 3

        rule_ids = {r["id"] for r in data["rules"]}
        assert rule_ids == {5010, 5011, 5012}


# =============================================================================
# 9) Fieldref Tests
# =============================================================================

class TestFieldrefE2E:
    """E2E tests for fieldref modifier through the full pipeline."""

    def test_fieldref_string_e2e(self, tmp_path):
        rule = """
id: 6000
description: "fieldref string e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|fieldref: parent_process.file.filename
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        assert len(ctx.rules) == 1
        pred = ctx.id_to_predicate[0]
        assert pred.is_fieldref_predicate()
        assert pred.fieldref == "PARENT_PROCESS_FILE_FILENAME"
        assert pred.comparison_type == "exactmatch"
        assert pred.string_idx == -1
        assert pred.numerical_value == -1

    def test_fieldref_numeric_e2e(self, tmp_path):
        rule = """
id: 6001
description: "fieldref numeric e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|fieldref: parent_process.pid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        pred = ctx.id_to_predicate[0]
        assert pred.fieldref == "PARENT_PROCESS_PID"
        assert pred.comparison_type == "equal"

    def test_fieldref_enum_e2e(self, tmp_path):
        rule = """
id: 6002
description: "fieldref enum e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|fieldref: parent_process.file.type
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        pred = ctx.id_to_predicate[0]
        assert pred.fieldref == "PARENT_PROCESS_FILE_TYPE"
        assert pred.comparison_type == "equal"

    def test_fieldref_with_startswith_e2e(self, tmp_path):
        rule = """
id: 6003
description: "fieldref startswith e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.path|fieldref|startswith: parent_process.file.path
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "startswith"
        assert pred.fieldref == "PARENT_PROCESS_FILE_PATH"

    def test_fieldref_with_endswith_e2e(self, tmp_path):
        rule = """
id: 6004
description: "fieldref endswith e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|fieldref|endswith: parent_process.file.filename
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "endswith"
        assert pred.fieldref == "PARENT_PROCESS_FILE_FILENAME"

    def test_fieldref_with_gte_e2e(self, tmp_path):
        rule = """
id: 6005
description: "fieldref gte e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.euid|fieldref|gte: parent_process.euid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "equal_above"
        assert pred.fieldref == "PARENT_PROCESS_EUID"

    def test_fieldref_with_neq_e2e(self, tmp_path):
        rule = """
id: 6006
description: "fieldref neq e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|neq|fieldref: parent_process.pid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        assert ctx.rules[0].condition_expr.operator_type == "NOT"
        child = ctx.rules[0].condition_expr.children[0]
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.fieldref == "PARENT_PROCESS_PID"

    def test_fieldref_mixed_with_regular_fields_e2e(self, tmp_path):
        rule = """
id: 6007
description: "fieldref mixed"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|fieldref: parent_process.file.filename
        process.cmd|contains: "suspicious"
        process.pid|gt: 100
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)

        assert len(ctx.id_to_predicate) == 3
        fieldref_preds = [p for p in ctx.id_to_predicate.values() if p.is_fieldref_predicate()]
        string_preds = [p for p in ctx.id_to_predicate.values() if p.is_string_predicate()]
        numeric_preds = [p for p in ctx.id_to_predicate.values() if p.is_numeric_predicate()]
        assert len(fieldref_preds) == 1
        assert len(string_preds) == 1
        assert len(numeric_preds) == 1

    def test_fieldref_json_output_e2e(self, tmp_path):
        """Test fieldref through the full pipeline to JSON output."""
        rule = """
id: 6008
description: "fieldref json output"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|fieldref|gte: parent_process.pid
        process.file.filename|fieldref|startswith: parent_process.file.filename
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        data = serialize_context(postfix_ctx)

        assert len(data["rules"]) == 1
        assert len(data["id_to_predicate"]) == 2
        assert len(data["id_to_string"]) == 0

        preds = data["id_to_predicate"]
        for pred in preds.values():
            assert pred["fieldref"] != "FIELD_TYPE_NONE"
            assert pred["string_idx"] == -1
            assert pred["numerical_value"] == -1

    def test_fieldref_type_mismatch_rejected_e2e(self, tmp_path):
        rule = """
id: 6009
description: "fieldref type mismatch"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|fieldref: parent_process.pid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref type mismatch"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_invalid_target_rejected_e2e(self, tmp_path):
        rule = """
id: 6010
description: "fieldref invalid target"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|fieldref: nonexistent_field
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref target.*not a valid field"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_contains_rejected_e2e(self, tmp_path):
        rule = """
id: 6011
description: "fieldref contains rejected"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|fieldref|contains: parent_process.cmd
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="contains.*cannot.*fieldref"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_ip_field_rejected_e2e(self, tmp_path):
        rule = """
id: 6012
description: "fieldref on IP field"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|fieldref: network.destination_ip
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref.*cannot.*IP"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_enum_with_extra_modifier_rejected_e2e(self, tmp_path):
        rule = """
id: 6013
description: "fieldref enum with gt rejected"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|fieldref|gt: parent_process.file.type
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="[Ee]num.*fieldref.*do not support"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_list_value_rejected_e2e(self, tmp_path):
        rule = """
id: 6014
description: "fieldref list value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|fieldref:
            - parent_process.cmd
            - parent_process.file.filename
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref.*single field name string"):
            load_sigma_rules(str(tmp_path))

