"""Test suite for sigma_rule_loader module."""
import os
import tempfile
import shutil
import pytest

from sigma_rule_loader import (
    load_sigma_rules,
    parse_field_key,
    validate_rule,
    load_rule_file,
    validate_rules_per_event_limit,
    validate_version_field,
    SigmaRule,
)
from constants import MAX_RULES_PER_MAP, VALID_EVENT_TYPES


class TestParseFieldKey:
    """Tests for parse_field_key function."""
    
    def test_string_field_no_modifier(self):
        result = parse_field_key("process.file.filename")
        assert result.field_name == "process.file.filename"
        assert result.field_type == "string"
        assert result.comparison == "exactmatch"
    
    def test_string_field_contains(self):
        result = parse_field_key("process.cmd|contains")
        assert result.field_name == "process.cmd"
        assert result.field_type == "string"
        assert result.comparison == "contains"
    
    def test_string_field_contains_all(self):
        result = parse_field_key("process.cmd|contains|all")
        assert result.field_name == "process.cmd"
        assert result.comparison == "contains"
    
    def test_string_field_startswith(self):
        result = parse_field_key("process.file.path|startswith")
        assert result.comparison == "startswith"
    
    def test_string_field_endswith(self):
        result = parse_field_key("process.file.filename|endswith")
        assert result.comparison == "endswith"
    
    def test_parent_process_field(self):
        result = parse_field_key("parent_process.file.filename")
        assert result.field_name == "parent_process.file.filename"
        assert result.field_type == "string"
        assert result.comparison == "exactmatch"
    
    def test_numeric_field_no_modifier(self):
        result = parse_field_key("process.pid")
        assert result.field_name == "process.pid"
        assert result.field_type == "numeric"
        assert result.comparison == "equal"
    
    def test_numeric_field_gt(self):
        result = parse_field_key("process.pid|gt")
        assert result.comparison == "above"
    
    def test_numeric_field_gte(self):
        result = parse_field_key("process.euid|gte")
        assert result.comparison == "equal_above"
    
    def test_numeric_field_lt(self):
        result = parse_field_key("process.rgid|lt")
        assert result.comparison == "below"
    
    def test_numeric_field_lte(self):
        result = parse_field_key("chmod.requested_mode|lte")
        assert result.comparison == "equal_below"
    
    def test_enum_field(self):
        result = parse_field_key("process.file.type")
        assert result.field_type == "enum"
        assert result.comparison == "equal"
    
    def test_target_file_enum(self):
        result = parse_field_key("target.file.type")
        assert result.field_type == "enum"
    
    def test_invalid_field_raises(self):
        with pytest.raises(Exception, match="Invalid field"):
            parse_field_key("InvalidField")
    
    def test_invalid_string_modifier_raises(self):
        with pytest.raises(Exception, match="(?i)invalid.*modifier"):
            parse_field_key("process.cmd|regex")
    
    def test_numeric_modifier_on_string_raises(self):
        with pytest.raises(Exception, match="(?i)invalid.*string"):
            parse_field_key("process.cmd|gt")
    
    def test_string_modifier_on_numeric_raises(self):
        with pytest.raises(Exception, match="(?i)invalid.*numeric"):
            parse_field_key("process.pid|contains")


class TestLoadValidRules:
    """Tests for loading valid rule files."""
    
    @pytest.fixture
    def valid_rules_dir(self):
        return os.path.join(os.path.dirname(__file__), 'valid_rules')
    
    def test_load_all_rules(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        assert len(rules) == 31
    
    def test_rule_ids_are_unique(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids))
    
    def test_expected_ids_present(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ids = {r.id for r in rules}
        expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 40, 41, 42, 43}
        assert ids == expected
    
    def test_rule_1_details(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        rule1 = next(r for r in rules if r.id == 1)
        assert "ProcDump" in rule1.description
        assert rule1.action == "BLOCK_EVENT"
        assert "condition" in rule1.detection


class TestInvalidRules:
    """Tests for invalid rule rejection."""
    
    @pytest.fixture
    def invalid_rules_dir(self):
        return os.path.join(os.path.dirname(__file__), 'invalid_rules')
    
    def test_invalid_field_rejected(self, invalid_rules_dir):
        filepath = os.path.join(invalid_rules_dir, "invalid_field.yml")
        rule_data = load_rule_file(filepath)
        with pytest.raises(Exception, match="(?i)invalid field"):
            validate_rule(rule_data, filepath)
    
    def test_invalid_action_rejected(self, invalid_rules_dir):
        filepath = os.path.join(invalid_rules_dir, "invalid_action.yml")
        rule_data = load_rule_file(filepath)
        with pytest.raises(Exception, match="(?i)invalid action"):
            validate_rule(rule_data, filepath)
    
    def test_missing_condition_rejected(self, invalid_rules_dir):
        filepath = os.path.join(invalid_rules_dir, "missing_condition.yml")
        rule_data = load_rule_file(filepath)
        with pytest.raises(Exception, match="condition"):
            validate_rule(rule_data, filepath)
    
    def test_invalid_modifier_rejected(self, invalid_rules_dir):
        filepath = os.path.join(invalid_rules_dir, "invalid_modifier.yml")
        rule_data = load_rule_file(filepath)
        with pytest.raises(Exception, match="(?i)invalid.*modifier"):
            validate_rule(rule_data, filepath)


class TestDuplicateIdDetection:
    """Tests for duplicate rule ID detection."""
    
    def test_duplicate_ids_rejected(self, tmp_path):
        rule1 = """
id: 999
description: "First rule"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test1.exe"
    condition: sel
"""
        rule2 = """
id: 999
description: "Second rule with same ID"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test2.exe"
    condition: sel
"""
        (tmp_path / "rule1.yml").write_text(rule1)
        (tmp_path / "rule2.yml").write_text(rule2)
        
        with pytest.raises(Exception, match="Duplicate rule id.*999"):
            load_sigma_rules(str(tmp_path))


class TestNotConditions:
    """Tests for NOT condition parsing."""
    
    def test_simple_not(self, tmp_path):
        rule = """
id: 100
description: "Simple NOT test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    suspicious:
        process.cmd|contains: "evil"
    trusted:
        process.file.path|startswith: "/usr/"
    condition: suspicious and not trusted
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_multiple_nots(self, tmp_path):
        rule = """
id: 102
description: "Multiple NOT test"
action: "ALLOW_EVENT"
events: [CHMOD]
detection:
    target:
        process.file.filename|endswith: ".sh"
    exclude1:
        process.file.path|startswith: "/tmp/"
    exclude2:
        process.file.path|startswith: "/var/tmp/"
    condition: target and not exclude1 and not exclude2
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestAllOfConditions:
    """Tests for 'all of' and '1 of' conditions."""
    
    def test_all_of_them(self, tmp_path):
        rule = """
id: 200
description: "All of them test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "evil"
    sel2:
        process.file.path|startswith: "/tmp/"
    sel3:
        process.file.filename: "malware"
    condition: all of them
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_all_of_pattern(self, tmp_path):
        rule = """
id: 201
description: "All of pattern test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel_path:
        process.file.path|contains: "/bin"
    sel_cmd:
        process.cmd|contains: "chmod"
    filter:
        process.euid: 0
    condition: all of sel* and not filter
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestAllOfInvalidCases:
    """Tests for invalid 'all of' patterns."""
    
    def test_nonexistent_pattern_rejected(self, tmp_path):
        from AST import parse_rules
        
        rule = """
id: 300
description: "Invalid pattern test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "test"
    condition: all of nonexistent*
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="(?i)(no result|nonexistent|failed)"):
            parse_rules(rules)

class TestNoneExistentSelection:
    """Tests for none existent selection in 'all of' patterns."""
    
    def test_nonexistent_selection_rejected(self, tmp_path):
        from AST import parse_rules
        
        rule = """
id: 300
description: "Nonexistent selection test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "test"
    condition: sel1 and sel2
"""     
        with pytest.raises(Exception, match="(?i)(not defined|nonexistent|failed)"):
            (tmp_path / "rule.yml").write_text(rule)
            rules = load_sigma_rules(str(tmp_path))
            parse_rules(rules)


class TestXOfConditions:
    """Tests for 'X of' conditions (2 of, 3 of, etc.)."""
    
    def test_2_of_them(self, tmp_path):
        rule = """
id: 400
description: "2 of them test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "evil"
    sel2:
        process.file.path|startswith: "/tmp/"
    sel3:
        process.file.filename: "malware"
    condition: 2 of them
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_3_of_them(self, tmp_path):
        rule = """
id: 402
description: "3 of them test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    ind1:
        process.file.path|contains: "/tmp"
    ind2:
        process.cmd|contains: "curl"
    ind3:
        process.file.filename|endswith: ".sh"
    ind4:
        process.euid: 0
    condition: 3 of them
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestXOfInvalidCases:
    """Tests for invalid 'X of' patterns."""
    
    def test_too_many_required_rejected(self, tmp_path):
        from AST import parse_rules
        
        rule = """
id: 500
description: "Too many required"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "test1"
    sel2:
        process.cmd|contains: "test2"
    sel3:
        process.cmd|contains: "test3"
    condition: 5 of them
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="(?i)requires.*5"):
            parse_rules(rules)
    
    def test_zero_quantifier_rejected(self, tmp_path):
        from AST import parse_rules
        
        rule = """
id: 502
description: "Zero quantifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel1:
        process.cmd|contains: "test"
    condition: 0 of them
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="(?i)at least 1"):
            parse_rules(rules)


class TestEventFieldValidation:
    """Tests for event-based field validation."""
    
    def test_valid_chmod_with_target_file(self, tmp_path):
        rule = """
id: 600
description: "Valid chmod rule with target.file"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        target.file.path|startswith: "/etc/"
        chmod.requested_mode|gte: 777
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_valid_multiple_file_events(self, tmp_path):
        rule = """
id: 601
description: "Valid multi-event rule"
action: "BLOCK_EVENT"
events: [READ, WRITE, CHMOD]
detection:
    sel:
        target.file.path|startswith: "/etc/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_chmod_specific_with_multiple_events_rejected(self, tmp_path):
        rule = """
id: 602
description: "Invalid - specific field with multiple events"
action: "BLOCK_EVENT"
events: [CHMOD, READ]
detection:
    sel:
        target.file.path|startswith: "/etc/"
        chmod.requested_mode|gte: 777
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="chmod.requested_mode"):
            load_sigma_rules(str(tmp_path))
    
    def test_target_file_with_exec_rejected(self, tmp_path):
        rule = """
id: 603
description: "Invalid - target.file with EXEC"
action: "BLOCK_EVENT"
events: [EXEC]
detection:
    sel:
        target.file.path|startswith: "/etc/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="target.file.path"):
            load_sigma_rules(str(tmp_path))
    
    def test_valid_exec_with_target_process(self, tmp_path):
        rule = """
id: 604
description: "Valid EXEC rule with target.process"
action: "BLOCK_EVENT"
events: [EXEC]
detection:
    sel:
        target.process.cmd|contains: "bash"
        target.process.file.path|startswith: "/bin/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_any_events_with_process_fields_only(self, tmp_path):
        rule = """
id: 606
description: "Valid - any events with only process fields"
action: "BLOCK_EVENT"
events: [EXEC, CHMOD, READ]
detection:
    sel:
        process.cmd|contains: "suspicious"
        process.file.path|startswith: "/tmp/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_valid_rename_with_specific_fields(self, tmp_path):
        rule = """
id: 607
description: "Valid RENAME rule"
action: "BLOCK_EVENT"
events: [RENAME]
detection:
    sel:
        rename.source_file.path|startswith: "/etc/"
        rename.destination_file.path|startswith: "/tmp/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_target_file_with_rename_rejected(self, tmp_path):
        rule = """
id: 608
description: "Invalid - RENAME with target.file"
action: "BLOCK_EVENT"
events: [RENAME]
detection:
    sel:
        target.file.path|startswith: "/etc/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="target.file.path"):
            load_sigma_rules(str(tmp_path))


class TestMaxRulesPerEventLimit:
    """Tests for MAX_RULES_PER_MAP validation."""
    
    def _create_rule(self, rule_id: int, events: list) -> SigmaRule:
        """Helper to create a minimal SigmaRule object."""
        return SigmaRule(
            id=rule_id,
            description=f"Test rule {rule_id}",
            action="BLOCK_EVENT",
            events=events,
            detection={"sel": {"process.pid": 1}, "condition": "sel"},
            source_file=f"test_{rule_id}.yml"
        )
    
    def test_exceeding_max_rules_for_single_event_raises(self):
        """Test that exceeding MAX_RULES_PER_MAP for a single event type raises."""
        rules = [
            self._create_rule(i, ["CHMOD"]) 
            for i in range(MAX_RULES_PER_MAP + 1)
        ]
        
        with pytest.raises(Exception, match=f"CHMOD.*{MAX_RULES_PER_MAP + 1}.*exceeds.*{MAX_RULES_PER_MAP}"):
            validate_rules_per_event_limit(rules)
    
    def test_max_rules_for_all_events_no_throw(self):
        """Test that exactly MAX_RULES_PER_MAP rules for all event types is allowed."""
        rules = []
        rule_id = 0
        all_events = list(VALID_EVENT_TYPES)
        
        for _ in range(MAX_RULES_PER_MAP):
            rules.append(self._create_rule(rule_id, all_events))
            rule_id += 1
        
        # Should not raise - exactly at the limit for all events
        validate_rules_per_event_limit(rules)


class TestKeywordValidation:
    """Tests for keyword selection validation."""
    
    def test_valid_keyword_selection(self, tmp_path):
        """Test that valid keyword selection is accepted."""
        rule = """
id: 700
description: "Valid keyword rule"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "malware"
        - "suspicious"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_valid_keyword_with_all_modifier(self, tmp_path):
        """Test that keyword selection with |all modifier is accepted."""
        rule = """
id: 701
description: "Keyword with all modifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        '|all':
            - "must_have_1"
            - "must_have_2"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_empty_keyword_list_rejected(self, tmp_path):
        """Test that empty keyword list is rejected."""
        rule = """
id: 702
description: "Empty keyword list"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords: []
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="empty list"):
            load_sigma_rules(str(tmp_path))
    
    def test_empty_string_in_keywords_rejected(self, tmp_path):
        """Test that empty string in keywords is rejected."""
        rule = """
id: 703
description: "Empty string in keywords"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "valid"
        - ""
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="empty string"):
            load_sigma_rules(str(tmp_path))
    
    def test_duplicate_keyword_rejected(self, tmp_path):
        """Test that duplicate keywords in same selection are rejected."""
        rule = """
id: 704
description: "Duplicate keywords"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "malware"
        - "suspicious"
        - "malware"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="duplicate keyword.*malware"):
            load_sigma_rules(str(tmp_path))
    
    def test_same_keyword_different_selections_ok(self, tmp_path):
        """Test that same keyword in different selections is allowed."""
        rule = """
id: 705
description: "Same keyword in different selections"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords1:
        - "malware"
    keywords2:
        - "malware"
    condition: keywords1 or keywords2
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_keyword_with_valid_wildcards(self, tmp_path):
        """Test that keywords with valid wildcards are accepted."""
        rule = """
id: 708
description: "Keywords with wildcards"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "*malware*"
        - "suspicious*"
        - "*backdoor"
        - "test*value"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_keyword_with_too_many_wildcards_rejected(self, tmp_path):
        """Test that keywords with too many wildcards are rejected."""
        rule = """
id: 709
description: "Too many wildcards"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "*mal*ware*"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="too many wildcards"):
            load_sigma_rules(str(tmp_path))
    
    def test_keyword_with_unescaped_question_mark_rejected(self, tmp_path):
        """Test that keywords with unescaped ? are rejected."""
        rule = """
id: 710
description: "Unescaped question mark"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "mal?ware"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="single character wildcard"):
            load_sigma_rules(str(tmp_path))
    
    def test_keyword_with_escaped_wildcards_ok(self, tmp_path):
        """Test that keywords with escaped wildcards are accepted."""
        rule = """
id: 711
description: "Escaped wildcards"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - 'file\\*name'
        - 'query\\?param'
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_lone_asterisk_keyword_rejected(self, tmp_path):
        """Test that a lone asterisk keyword is rejected."""
        rule = """
id: 712
description: "Lone asterisk"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "*"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="not a valid pattern"):
            load_sigma_rules(str(tmp_path))
    
    def test_mixed_keywords_and_field_selections(self, tmp_path):
        """Test that keywords can be mixed with field-based selections."""
        rule = """
id: 713
description: "Mixed keywords and fields"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "malware"
    field_selection:
        process.cmd|contains: "suspicious"
    condition: keywords and field_selection
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestVersionValidation:
    """Tests for min_version and max_version validation."""
    
    def test_valid_version_simple(self):
        """Test valid simple version strings."""
        assert validate_version_field("1.0.0", "min_version", "test.yml") == "1.0.0"
        assert validate_version_field("0.0.0", "min_version", "test.yml") == "0.0.0"
        assert validate_version_field("10.20.30", "max_version", "test.yml") == "10.20.30"
        assert validate_version_field("999.999.999", "min_version", "test.yml") == "999.999.999"
    
    def test_valid_version_with_zeros(self):
        """Test versions with zero components."""
        assert validate_version_field("0.0.1", "min_version", "test.yml") == "0.0.1"
        assert validate_version_field("1.0.0", "min_version", "test.yml") == "1.0.0"
        assert validate_version_field("0.1.0", "min_version", "test.yml") == "0.1.0"
    
    def test_invalid_version_leading_zeros(self):
        """Test that leading zeros are rejected."""
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("01.0.0", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1.02.0", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1.0.03", "max_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("01.02.03", "min_version", "test.yml")
    
    def test_invalid_version_format(self):
        """Test that invalid formats are rejected."""
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1.0", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1.0.0.0", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("v1.0.0", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("1.0.0-beta", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("", "min_version", "test.yml")
        
        with pytest.raises(Exception, match="invalid format"):
            validate_version_field("abc", "min_version", "test.yml")
    
    def test_invalid_version_type(self):
        """Test that non-string types are rejected."""
        with pytest.raises(Exception, match="must be a string"):
            validate_version_field(100, "min_version", "test.yml")
        
        with pytest.raises(Exception, match="must be a string"):
            validate_version_field(1.0, "min_version", "test.yml")
        
        with pytest.raises(Exception, match="must be a string"):
            validate_version_field(["1.0.0"], "min_version", "test.yml")
    
    def test_rule_with_valid_versions(self, tmp_path):
        """Test that rules with valid versions are accepted."""
        rule = """
id: 800
description: "Rule with versions"
action: "BLOCK_EVENT"
events: [CHMOD]
min_version: "1.0.0"
max_version: "2.0.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].min_version == "1.0.0"
        assert rules[0].max_version == "2.0.0"
    
    def test_rule_with_only_min_version(self, tmp_path):
        """Test that rules with only min_version are accepted."""
        rule = """
id: 801
description: "Rule with min version only"
action: "BLOCK_EVENT"
events: [CHMOD]
min_version: "0.5.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].min_version == "0.5.0"
        assert rules[0].max_version is None
    
    def test_rule_with_only_max_version(self, tmp_path):
        """Test that rules with only max_version are accepted."""
        rule = """
id: 802
description: "Rule with max version only"
action: "BLOCK_EVENT"
events: [CHMOD]
max_version: "10.0.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].min_version is None
        assert rules[0].max_version == "10.0.0"
    
    def test_rule_without_versions(self, tmp_path):
        """Test that rules without versions are accepted."""
        rule = """
id: 803
description: "Rule without versions"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0].min_version is None
        assert rules[0].max_version is None
    
    def test_rule_with_invalid_min_version_rejected(self, tmp_path):
        """Test that rules with invalid min_version are rejected."""
        rule = """
id: 804
description: "Rule with invalid min version"
action: "BLOCK_EVENT"
events: [CHMOD]
min_version: "01.0.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="invalid format"):
            load_sigma_rules(str(tmp_path))
    
    def test_rule_with_invalid_max_version_rejected(self, tmp_path):
        """Test that rules with invalid max_version are rejected."""
        rule = """
id: 805
description: "Rule with invalid max version"
action: "BLOCK_EVENT"
events: [CHMOD]
max_version: "1.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="invalid format"):
            load_sigma_rules(str(tmp_path))


class TestNeqModifierValidation:
    """Tests for |neq modifier validation in parse_field_key."""
    
    def test_neq_on_string_field(self):
        result = parse_field_key("process.file.filename|neq")
        assert result.field_name == "process.file.filename"
        assert result.field_type == "string"
        assert result.comparison == "exactmatch"
    
    def test_neq_on_numeric_field(self):
        result = parse_field_key("process.pid|neq")
        assert result.field_name == "process.pid"
        assert result.field_type == "numeric"
        assert result.comparison == "equal"
    
    def test_neq_on_enum_field(self):
        result = parse_field_key("process.file.type|neq")
        assert result.field_name == "process.file.type"
        assert result.field_type == "enum"
        assert result.comparison == "equal"
    
    def test_neq_combined_with_contains_raises(self):
        with pytest.raises(Exception, match="(?i)modifier"):
            parse_field_key("process.cmd|neq|contains")
    
    def test_neq_combined_with_startswith_raises(self):
        with pytest.raises(Exception, match="(?i)modifier"):
            parse_field_key("process.cmd|neq|startswith")
    
    def test_contains_combined_with_neq_raises(self):
        with pytest.raises(Exception, match="neq.*cannot be combined"):
            parse_field_key("process.cmd|contains|neq")
    
    def test_neq_combined_with_gt_raises(self):
        with pytest.raises(Exception, match="(?i)modifier"):
            parse_field_key("process.pid|neq|gt")
    
    def test_neq_combined_with_all_raises(self):
        with pytest.raises(Exception, match="neq.*cannot be combined"):
            parse_field_key("process.cmd|all|neq")
    
    def test_neq_combined_with_cidr_raises(self):
        with pytest.raises(Exception, match="(?i)modifier"):
            parse_field_key("network.source_ip|neq|cidr")
    
    def test_rule_with_neq_string_loads(self, tmp_path):
        rule = """
id: 900
description: "neq string test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|neq: "bad_process"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_rule_with_neq_numeric_loads(self, tmp_path):
        rule = """
id: 901
description: "neq numeric test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|neq: 100
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_rule_with_neq_enum_loads(self, tmp_path):
        rule = """
id: 902
description: "neq enum test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|neq: "REGULAR_FILE"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_rule_with_neq_list_value_rejected(self, tmp_path):
        """neq with a list of values should be rejected at validation."""
        rule = """
id: 903
description: "neq with list value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|neq:
            - "bash"
            - "sh"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            load_sigma_rules(str(tmp_path))
    
    def test_rule_with_neq_numeric_list_value_rejected(self, tmp_path):
        """neq with a list of numeric values should be rejected."""
        rule = """
id: 904
description: "neq with numeric list"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|neq:
            - 0
            - 1
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            load_sigma_rules(str(tmp_path))
    
    def test_rule_with_neq_dict_value_rejected(self, tmp_path):
        """neq with a dict value should be rejected at validation."""
        rule = """
id: 907
description: "neq with dict value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|neq:
            key: "value"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            load_sigma_rules(str(tmp_path))
    
    def test_rule_with_neq_in_list_selection_rejected(self, tmp_path):
        """neq in list-style (OR) selections should be rejected."""
        from AST import parse_rules
        
        rule = """
id: 905
description: "neq in list selection"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        - process.pid|neq: 100
        - process.cmd: "test"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="neq.*not supported.*list"):
            parse_rules(rules)
    
    def test_neq_on_ip_field(self):
        result = parse_field_key("network.source_ip|neq")
        assert result.field_name == "network.source_ip"
        assert result.field_type == "string"
        assert result.comparison == "exactmatch"
    
    def test_rule_with_neq_ip_loads(self, tmp_path):
        rule = """
id: 906
description: "neq IP test"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|neq: "192.168.1.1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestFieldrefModifierValidation:
    """Tests for |fieldref modifier validation in parse_field_key and validate_selection_item."""

    def test_fieldref_string_field(self):
        result = parse_field_key("process.file.filename|fieldref")
        assert result.field_name == "process.file.filename"
        assert result.field_type == "string"
        assert result.comparison == "exactmatch"
        assert result.is_fieldref == True

    def test_fieldref_numeric_field(self):
        result = parse_field_key("process.pid|fieldref")
        assert result.field_name == "process.pid"
        assert result.field_type == "numeric"
        assert result.comparison == "equal"
        assert result.is_fieldref == True

    def test_fieldref_enum_field(self):
        result = parse_field_key("process.file.type|fieldref")
        assert result.field_name == "process.file.type"
        assert result.field_type == "enum"
        assert result.comparison == "equal"
        assert result.is_fieldref == True

    def test_fieldref_with_startswith(self):
        result = parse_field_key("process.cmd|fieldref|startswith")
        assert result.comparison == "startswith"
        assert result.is_fieldref == True

    def test_fieldref_with_endswith(self):
        result = parse_field_key("process.file.path|fieldref|endswith")
        assert result.comparison == "endswith"
        assert result.is_fieldref == True

    def test_fieldref_with_gt(self):
        result = parse_field_key("process.pid|fieldref|gt")
        assert result.comparison == "above"
        assert result.is_fieldref == True

    def test_fieldref_with_gte(self):
        result = parse_field_key("process.euid|fieldref|gte")
        assert result.comparison == "equal_above"
        assert result.is_fieldref == True

    def test_fieldref_with_lt(self):
        result = parse_field_key("process.rgid|fieldref|lt")
        assert result.comparison == "below"
        assert result.is_fieldref == True

    def test_fieldref_with_lte(self):
        result = parse_field_key("chmod.requested_mode|fieldref|lte")
        assert result.comparison == "equal_below"
        assert result.is_fieldref == True

    def test_fieldref_with_neq(self):
        result = parse_field_key("process.pid|fieldref|neq")
        assert result.is_fieldref == True

    def test_fieldref_neq_reversed_order(self):
        result = parse_field_key("process.pid|neq|fieldref")
        assert result.is_fieldref == True

    def test_fieldref_on_ip_field_rejected(self):
        with pytest.raises(Exception, match="fieldref.*cannot.*IP"):
            parse_field_key("network.source_ip|fieldref")

    def test_fieldref_with_contains_rejected(self):
        with pytest.raises(Exception, match="contains.*cannot.*fieldref"):
            parse_field_key("process.cmd|fieldref|contains")

    def test_fieldref_with_all_rejected(self):
        with pytest.raises(Exception, match="all.*cannot.*fieldref"):
            parse_field_key("process.cmd|fieldref|all")

    def test_fieldref_with_cidr_rejected(self):
        with pytest.raises(Exception, match="fieldref.*cannot.*IP"):
            parse_field_key("network.source_ip|fieldref|cidr")

    def test_fieldref_duplicate_rejected(self):
        with pytest.raises(Exception, match="[Dd]uplicate.*fieldref"):
            parse_field_key("process.cmd|fieldref|fieldref")

    def test_enum_fieldref_with_gt_rejected(self):
        with pytest.raises(Exception, match="[Ee]num.*fieldref.*do not support"):
            parse_field_key("process.file.type|fieldref|gt")

    def test_enum_fieldref_with_lte_rejected(self):
        with pytest.raises(Exception, match="[Ee]num.*fieldref.*do not support"):
            parse_field_key("process.file.type|fieldref|lte")

    def test_enum_fieldref_with_neq_allowed(self):
        result = parse_field_key("process.file.type|fieldref|neq")
        assert result.is_fieldref == True

    def test_fieldref_gte_reversed_order(self):
        result = parse_field_key("process.pid|gte|fieldref")
        assert result.comparison == "equal_above"
        assert result.is_fieldref == True

    def test_fieldref_lt_reversed_order(self):
        result = parse_field_key("process.pid|lt|fieldref")
        assert result.comparison == "below"
        assert result.is_fieldref == True

    def test_fieldref_startswith_reversed_order(self):
        result = parse_field_key("process.cmd|startswith|fieldref")
        assert result.comparison == "startswith"
        assert result.is_fieldref == True

    def test_fieldref_multiple_numeric_modifiers_rejected(self):
        with pytest.raises(Exception, match="[Mm]ultiple modifiers"):
            parse_field_key("process.pid|fieldref|gte|lt")

    def test_fieldref_multiple_string_modifiers_rejected(self):
        with pytest.raises(Exception, match="[Mm]ultiple modifiers"):
            parse_field_key("process.cmd|fieldref|startswith|endswith")

    def test_without_fieldref_has_false(self):
        result = parse_field_key("process.cmd|contains")
        assert result.is_fieldref == False

    def test_rule_with_fieldref_string_loads(self, tmp_path):
        rule = """
id: 1100
description: "fieldref string test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|fieldref: parent_process.file.filename
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_rule_with_fieldref_numeric_loads(self, tmp_path):
        rule = """
id: 1101
description: "fieldref numeric test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|fieldref: parent_process.pid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_rule_with_fieldref_enum_loads(self, tmp_path):
        rule = """
id: 1102
description: "fieldref enum test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|fieldref: parent_process.file.type
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_fieldref_invalid_target_rejected(self, tmp_path):
        rule = """
id: 1103
description: "fieldref invalid target"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|fieldref: nonexistent.field
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref target.*not a valid field"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_type_mismatch_rejected(self, tmp_path):
        rule = """
id: 1104
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

    def test_fieldref_list_value_rejected(self, tmp_path):
        rule = """
id: 1105
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

    def test_fieldref_target_ip_field_rejected(self, tmp_path):
        rule = """
id: 1106
description: "fieldref target is IP field"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        process.cmd|fieldref: network.source_ip
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref cannot reference IP fields"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_with_startswith_loads(self, tmp_path):
        rule = """
id: 1107
description: "fieldref startswith"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.path|fieldref|startswith: parent_process.file.path
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_fieldref_with_numeric_modifier_loads(self, tmp_path):
        rule = """
id: 1108
description: "fieldref gte"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|fieldref|gte: parent_process.pid
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

    def test_fieldref_numeric_value_rejected(self, tmp_path):
        rule = """
id: 1109
description: "fieldref with numeric value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.pid|fieldref: 123
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref.*single field name string"):
            load_sigma_rules(str(tmp_path))

    def test_fieldref_enum_type_mismatch_rejected(self, tmp_path):
        rule = """
id: 1110
description: "fieldref enum to string mismatch"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.type|fieldref: process.cmd
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="fieldref type mismatch"):
            load_sigma_rules(str(tmp_path))


class TestNetworkEventValidation:
    """Tests for NETWORK event type validation."""
    
    def test_valid_network_with_network_fields(self, tmp_path):
        """Test that NETWORK event accepts network-specific fields."""
        rule = """
id: 1000
description: "Valid NETWORK rule"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "192.168.1.1"
        network.destination_port: 443
        network.direction: "OUTGOING"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_network_with_process_fields(self, tmp_path):
        """Test that NETWORK event accepts process fields (always allowed)."""
        rule = """
id: 1001
description: "NETWORK with process fields"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        process.cmd|contains: "curl"
        network.destination_port: 80
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_network_with_target_file_rejected(self, tmp_path):
        """Test that NETWORK event rejects target.file fields."""
        rule = """
id: 1002
description: "Invalid - NETWORK with target.file"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        target.file.path|startswith: "/etc/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="target.file.path"):
            load_sigma_rules(str(tmp_path))
    
    def test_file_event_with_network_fields_rejected(self, tmp_path):
        """Test that file events reject network-specific fields."""
        rule = """
id: 1003
description: "Invalid - CHMOD with network fields"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        network.source_ip: "192.168.1.1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="network.source_ip"):
            load_sigma_rules(str(tmp_path))
    
    def test_exec_with_network_fields_rejected(self, tmp_path):
        """Test that EXEC event rejects network-specific fields."""
        rule = """
id: 1004
description: "Invalid - EXEC with network fields"
action: "BLOCK_EVENT"
events: [EXEC]
detection:
    sel:
        network.destination_port: 443
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="network.destination_port"):
            load_sigma_rules(str(tmp_path))
    
    def test_multiple_events_with_network_rejected(self, tmp_path):
        """Test that combining NETWORK with other events rejects network fields."""
        rule = """
id: 1005
description: "Invalid - multiple events with network fields"
action: "BLOCK_EVENT"
events: [NETWORK, CHMOD]
detection:
    sel:
        network.source_ip: "192.168.1.1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="network.source_ip"):
            load_sigma_rules(str(tmp_path))
    
    def test_multiple_events_with_only_process_fields(self, tmp_path):
        """Test that combining NETWORK with other events works with only process fields."""
        rule = """
id: 1006
description: "Valid - multiple events with process fields only"
action: "BLOCK_EVENT"
events: [NETWORK, CHMOD, EXEC]
detection:
    sel:
        process.cmd|contains: "suspicious"
        process.file.path|startswith: "/tmp/"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestNetworkKeywordExpansion:
    """Tests for keyword expansion with NETWORK events."""
    
    def test_keywords_work_with_network(self, tmp_path):
        """Test that keywords work with NETWORK event type."""
        from AST import parse_rules
        
        rule = """
id: 1100
description: "Keywords with NETWORK"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    keywords:
        - "malware"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        
        # Parse should work without error
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1
    
    def test_keywords_dont_expand_to_ip_fields(self, tmp_path):
        """Test that keywords do NOT expand to IP fields."""
        from AST import parse_rules
        from sigma_rule_loader import IP_FIELDS
        
        rule = """
id: 1101
description: "Keywords should not expand to IP fields"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    keywords:
        - "test_value"
    condition: keywords
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        # Check that no predicate uses IP fields
        for pred in ctx.id_to_predicate.values():
            assert pred.field not in IP_FIELDS, f"Keyword should not expand to IP field {pred.field}"
        
        # But predicates for process string fields should exist
        fields_used = {pred.field for pred in ctx.id_to_predicate.values()}
        assert "process.cmd" in fields_used
        assert "process.file.path" in fields_used
    
    def test_ip_fields_can_be_used_directly(self, tmp_path):
        """Test that IP fields can be used directly in field selections."""
        rule = """
id: 1102
description: "Direct IP field usage"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "192.168.1.1"
        network.destination_ip|contains: "10.0."
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1


class TestCIDRModifier:
    """Tests for CIDR modifier on IP fields."""
    
    def test_cidr_modifier_on_ip_field_accepted(self, tmp_path):
        """Test that CIDR modifier is accepted on IP fields."""
        rule = """
id: 1200
description: "CIDR modifier on IP field"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|cidr: "192.168.0.0/24"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
    
    def test_cidr_modifier_on_non_ip_field_rejected(self, tmp_path):
        """Test that CIDR modifier is rejected on non-IP fields."""
        rule = """
id: 1201
description: "CIDR modifier on non-IP field"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        process.cmd|cidr: "192.168.0.0/24"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="cidr.*IP field"):
            load_sigma_rules(str(tmp_path))
    
    def test_cidr_ipv4_parsing(self, tmp_path):
        """Test that IPv4 CIDR is correctly parsed."""
        from AST import parse_rules, AF_INET
        
        rule = """
id: 1202
description: "IPv4 CIDR parsing"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|cidr: "10.0.0.0/8"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.id_to_ip) == 1
        rule_ip = ctx.id_to_ip[0]
        assert rule_ip.ip == "10.0.0.0"
        assert rule_ip.cidr == 8
        assert rule_ip.ip_type == AF_INET
    
    def test_cidr_ipv6_parsing(self, tmp_path):
        """Test that IPv6 CIDR is correctly parsed and expanded."""
        from AST import parse_rules, AF_INET6
        
        rule = """
id: 1203
description: "IPv6 CIDR parsing"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.destination_ip|cidr: "2001:db8::/32"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.id_to_ip) == 1
        rule_ip = ctx.id_to_ip[0]
        # IPv6 should be fully expanded
        assert rule_ip.ip == "2001:0db8:0000:0000:0000:0000:0000:0000"
        assert rule_ip.cidr == 32
        assert rule_ip.ip_type == AF_INET6
    
    def test_exact_ip_match_ipv4(self, tmp_path):
        """Test that exact IPv4 match (no CIDR modifier) uses /32."""
        from AST import parse_rules, AF_INET
        
        rule = """
id: 1204
description: "Exact IPv4 match"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "192.168.1.1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.id_to_ip) == 1
        rule_ip = ctx.id_to_ip[0]
        assert rule_ip.ip == "192.168.1.1"
        assert rule_ip.cidr == 32  # Exact match
        assert rule_ip.ip_type == AF_INET
    
    def test_exact_ip_match_ipv6(self, tmp_path):
        """Test that exact IPv6 match (no CIDR modifier) uses /128."""
        from AST import parse_rules, AF_INET6
        
        rule = """
id: 1205
description: "Exact IPv6 match"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.destination_ip: "::1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        assert len(ctx.id_to_ip) == 1
        rule_ip = ctx.id_to_ip[0]
        # IPv6 localhost expanded
        assert rule_ip.ip == "0000:0000:0000:0000:0000:0000:0000:0001"
        assert rule_ip.cidr == 128  # Exact match
        assert rule_ip.ip_type == AF_INET6
    
    def test_invalid_ip_address_rejected(self, tmp_path):
        """Test that invalid IP addresses are rejected."""
        from AST import parse_rules
        
        rule = """
id: 1206
description: "Invalid IP address"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "not.an.ip.address"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="Invalid IP address"):
            parse_rules(rules)
    
    def test_wildcard_in_ip_rejected(self, tmp_path):
        """Test that wildcards are not allowed in IP addresses."""
        from AST import parse_rules
        
        rule = """
id: 1208
description: "Wildcard in IP"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "192.168.*"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="[Ww]ildcard.*not allowed"):
            parse_rules(rules)
    
    def test_ip_deduplication(self, tmp_path):
        """Test that duplicate IPs are deduplicated in id_to_ip."""
        from AST import parse_rules
        
        rule = """
id: 1207
description: "Duplicate IPs"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel1:
        network.source_ip|cidr: "192.168.0.0/24"
    sel2:
        network.destination_ip|cidr: "192.168.0.0/24"
    condition: sel1 or sel2
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        
        # Same IP/CIDR/type should be deduplicated
        assert len(ctx.id_to_ip) == 1
    
    def test_cidr_with_asterisk_wildcard_rejected(self, tmp_path):
        """Test that CIDR with asterisk wildcard is rejected by pySigma during parsing."""
        from AST import parse_rules
        
        rule = """
id: 1209
description: "CIDR with asterisk wildcard"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|cidr: "192.168.*.0/24"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        with pytest.raises(Exception, match="Invalid CIDR"):
            parse_rules(rules)
    
    def test_cidr_with_question_mark_wildcard_rejected(self, tmp_path):
        """Test that CIDR with question mark wildcard is rejected during validation."""
        rule = """
id: 1210
description: "CIDR with question mark wildcard"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|cidr: "192.168.1.?/24"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        
        with pytest.raises(Exception, match="single character wildcard"):
            load_sigma_rules(str(tmp_path))


class TestIPSerialization:
    """Tests for IP serialization through the full pipeline."""
    
    def test_id_to_ip_serialized_to_json(self, tmp_path):
        """Test that id_to_ip is correctly serialized to JSON output."""
        import json
        from AST import parse_rules, AF_INET, AF_INET6
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 1300
description: "IP serialization test"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip|cidr: "192.168.0.0/24"
        network.destination_ip: "10.0.0.1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert "id_to_ip" in data
        assert len(data["id_to_ip"]) == 2
        
        ip_0 = data["id_to_ip"]["0"]
        assert ip_0["ip"] == "192.168.0.0"
        assert ip_0["cidr"] == 24
        assert ip_0["ip_type"] == AF_INET
        
        ip_1 = data["id_to_ip"]["1"]
        assert ip_1["ip"] == "10.0.0.1"
        assert ip_1["cidr"] == 32
        assert ip_1["ip_type"] == AF_INET
    
    def test_ipv6_serialized_expanded(self, tmp_path):
        """Test that IPv6 addresses are serialized in expanded form."""
        import json
        from AST import parse_rules, AF_INET6
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 1301
description: "IPv6 serialization test"
action: "BLOCK_EVENT"
events: [NETWORK]
detection:
    sel:
        network.source_ip: "::1"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert len(data["id_to_ip"]) == 1
        ip_0 = data["id_to_ip"]["0"]
        assert ip_0["ip"] == "0000:0000:0000:0000:0000:0000:0000:0001"
        assert ip_0["cidr"] == 128
        assert ip_0["ip_type"] == AF_INET6
    
    def test_empty_id_to_ip_serialized(self, tmp_path):
        """Test that empty id_to_ip is serialized when no IP rules present."""
        import json
        from AST import parse_rules
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 1302
description: "No IP test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert "id_to_ip" in data
        assert len(data["id_to_ip"]) == 0


class TestVersionEndToEnd:
    """Tests for version fields through the full pipeline (load → parse → postfix → serialize)."""
    
    def test_versions_serialized_to_json(self, tmp_path):
        """Test that versions are correctly serialized to JSON output."""
        import json
        from AST import parse_rules
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 900
description: "Rule with versions for serialization test"
action: "BLOCK_EVENT"
events: [CHMOD]
min_version: "1.0.0"
max_version: "2.5.10"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert len(data["rules"]) == 1
        assert data["rules"][0]["min_version"] == "1.0.0"
        assert data["rules"][0]["max_version"] == "2.5.10"
    
    def test_versions_not_serialized_when_absent(self, tmp_path):
        """Test that versions are NOT serialized when not present in rule."""
        import json
        from AST import parse_rules
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 901
description: "Rule without versions"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert len(data["rules"]) == 1
        assert "min_version" not in data["rules"][0]
        assert "max_version" not in data["rules"][0]
    
    def test_only_min_version_serialized(self, tmp_path):
        """Test that only min_version is serialized when max_version is absent."""
        import json
        from AST import parse_rules
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 902
description: "Rule with only min version"
action: "BLOCK_EVENT"
events: [CHMOD]
min_version: "0.5.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert len(data["rules"]) == 1
        assert data["rules"][0]["min_version"] == "0.5.0"
        assert "max_version" not in data["rules"][0]
    
    def test_only_max_version_serialized(self, tmp_path):
        """Test that only max_version is serialized when min_version is absent."""
        import json
        from AST import parse_rules
        from postfix import convert_to_postfix
        from serializer import to_json_string
        
        rule = """
id: 903
description: "Rule with only max version"
action: "BLOCK_EVENT"
events: [CHMOD]
max_version: "10.0.0"
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        
        parsed_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(parsed_ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        assert len(data["rules"]) == 1
        assert "min_version" not in data["rules"][0]
        assert data["rules"][0]["max_version"] == "10.0.0"


class TestRuleMetadataValidation:
    """Tests for optional rule metadata fields."""

    def test_description_is_optional(self, tmp_path):
        rule = """
id: 950
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))

        assert len(rules) == 1
        assert rules[0].description == ""
        assert rules[0].severity == "unknown"
        assert rules[0].mitre_tags == []

    def test_extended_metadata_is_loaded(self, tmp_path):
        rule = """
id: 951
description: "Metadata description"
title: "Metadata title"
severity: high
mitre_tags:
    - "attack.execution"
    - "attack.t1059.004"
name: "metadata_rule_name"
author: "John Doe"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))

        assert len(rules) == 1
        assert rules[0].description == "Metadata description"
        assert rules[0].title == "Metadata title"
        assert rules[0].severity == "high"
        assert rules[0].mitre_tags == ["attack.execution", "attack.t1059.004"]
        assert rules[0].name == "metadata_rule_name"
        assert rules[0].author == "John Doe"

    def test_invalid_severity_rejected(self, tmp_path):
        rule = """
id: 952
severity: "urgent"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="Invalid severity"):
            load_sigma_rules(str(tmp_path))

    def test_invalid_mitre_tags_rejected(self, tmp_path):
        rule = """
id: 953
mitre_tags: "attack.execution"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test.exe"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        with pytest.raises(Exception, match="mitre_tags.*list"):
            load_sigma_rules(str(tmp_path))
