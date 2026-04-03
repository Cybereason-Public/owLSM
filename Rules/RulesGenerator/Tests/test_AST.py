"""Test suite for AST module (pySigma-based AST walking)."""
import os
import pytest

from sigma_rule_loader import load_sigma_rules, SigmaRule
from AST import (
    parse_rules,
    parse_rule_with_pysigma,
    Predicate,
    ConditionExpr,
    ParsedRulesContext,
    StringEntry,
    get_string_fields_for_event,
)
from constants import MAX_TOTAL_PREDS, StringType


class TestStringDeduplication:
    """Tests for string deduplication in ParsedRulesContext."""
    
    def test_same_string_returns_same_index(self):
        ctx = ParsedRulesContext()
        idx1 = ctx.get_or_add_string("test")
        idx2 = ctx.get_or_add_string("test")
        assert idx1 == idx2
    
    def test_different_strings_different_indices(self):
        ctx = ParsedRulesContext()
        idx1 = ctx.get_or_add_string("test")
        idx2 = ctx.get_or_add_string("different")
        assert idx1 != idx2
    
    def test_unique_string_count(self):
        ctx = ParsedRulesContext()
        ctx.get_or_add_string("test")
        ctx.get_or_add_string("test")
        ctx.get_or_add_string("different")
        assert len(ctx.id_to_string) == 2


class TestIsContainsUpgrade:
    """Tests for is_contains upgrade behavior."""
    
    def test_upgrade_default_to_contains(self):
        ctx = ParsedRulesContext()
        idx1 = ctx.get_or_add_string("test", string_type=StringType.DEFAULT)
        idx2 = ctx.get_or_add_string("test", string_type=StringType.CONTAINS)
        assert idx1 == idx2
        assert len(ctx.id_to_string) == 1
        assert ctx.id_to_string[idx1].string_type == StringType.CONTAINS
    
    def test_no_downgrade_contains_to_default(self):
        ctx = ParsedRulesContext()
        idx1 = ctx.get_or_add_string("test", string_type=StringType.CONTAINS)
        idx2 = ctx.get_or_add_string("test", string_type=StringType.DEFAULT)
        assert idx1 == idx2
        assert len(ctx.id_to_string) == 1
        assert ctx.id_to_string[idx1].string_type == StringType.CONTAINS
    
    def test_regex_is_separate_from_literal(self):
        ctx = ParsedRulesContext()
        idx_default = ctx.get_or_add_string("test", string_type=StringType.DEFAULT)
        idx_regex = ctx.get_or_add_string("test", string_type=StringType.REGEX)
        assert idx_default != idx_regex
        assert len(ctx.id_to_string) == 2


class TestPredDeduplication:
    """Tests for predicate deduplication."""
    
    def test_same_pred_returns_same_index(self):
        ctx = ParsedRulesContext()
        str_idx = ctx.get_or_add_string("value")
        pred1 = Predicate(field="process.cmd", comparison_type="contains", string_idx=str_idx)
        pred2 = Predicate(field="process.cmd", comparison_type="contains", string_idx=str_idx)
        idx1 = ctx.get_or_add_predicate(pred1)
        idx2 = ctx.get_or_add_predicate(pred2)
        assert idx1 == idx2
    
    def test_different_preds_different_indices(self):
        ctx = ParsedRulesContext()
        str_idx = ctx.get_or_add_string("value")
        pred1 = Predicate(field="process.cmd", comparison_type="contains", string_idx=str_idx)
        pred2 = Predicate(field="process.cmd", comparison_type="exactmatch", string_idx=str_idx)
        idx1 = ctx.get_or_add_predicate(pred1)
        idx2 = ctx.get_or_add_predicate(pred2)
        assert idx1 != idx2


class TestPredValidation:
    """Tests for Predicate validation."""
    
    def test_string_pred(self):
        pred = Predicate(field="process.cmd", comparison_type="contains", string_idx=5)
        assert pred.is_string_predicate() == True
        assert pred.is_numeric_predicate() == False
    
    def test_numeric_pred(self):
        pred = Predicate(field="process.pid", comparison_type="above", numerical_value=1000)
        assert pred.is_string_predicate() == False
        assert pred.is_numeric_predicate() == True
    
    def test_both_string_and_numeric_raises(self):
        with pytest.raises(ValueError, match="exactly one value source"):
            Predicate(field="Test", comparison_type="equal", string_idx=5, numerical_value=1000)
    
    def test_neither_string_nor_numeric_raises(self):
        with pytest.raises(ValueError, match="exactly one value source"):
            Predicate(field="Test", comparison_type="equal")
    
    def test_fieldref_pred(self):
        pred = Predicate(field="process.cmd", comparison_type="exactmatch", fieldref="PARENT_PROCESS_CMD")
        assert pred.is_string_predicate() == False
        assert pred.is_numeric_predicate() == False
        assert pred.is_fieldref_predicate() == True
    
    def test_fieldref_with_string_raises(self):
        with pytest.raises(ValueError, match="exactly one value source"):
            Predicate(field="process.cmd", comparison_type="exactmatch", string_idx=5, fieldref="PARENT_PROCESS_CMD")
    
    def test_fieldref_with_numeric_raises(self):
        with pytest.raises(ValueError, match="exactly one value source"):
            Predicate(field="process.pid", comparison_type="equal", numerical_value=100, fieldref="PARENT_PROCESS_PID")


class TestFieldrefParsing:
    """Tests for fieldref modifier processing through the AST pipeline."""

    def test_fieldref_string_creates_predicate(self):
        rule = SigmaRule(
            id=1, description="fieldref string", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename|fieldref": "parent_process.file.filename"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        assert parsed.condition_expr.operator_type == "PRED"
        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.field == "process.file.filename"
        assert pred.comparison_type == "exactmatch"
        assert pred.fieldref == "PARENT_PROCESS_FILE_FILENAME"
        assert pred.is_fieldref_predicate()
        assert pred.string_idx == -1
        assert pred.numerical_value == -1

    def test_fieldref_numeric_creates_predicate(self):
        rule = SigmaRule(
            id=1, description="fieldref numeric", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref": "parent_process.pid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.field == "process.pid"
        assert pred.comparison_type == "equal"
        assert pred.fieldref == "PARENT_PROCESS_PID"
        assert pred.is_fieldref_predicate()

    def test_fieldref_enum_creates_predicate(self):
        rule = SigmaRule(
            id=1, description="fieldref enum", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.type|fieldref": "parent_process.file.type"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.field == "process.file.type"
        assert pred.comparison_type == "equal"
        assert pred.fieldref == "PARENT_PROCESS_FILE_TYPE"

    def test_fieldref_with_startswith(self):
        rule = SigmaRule(
            id=1, description="fieldref startswith", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.path|fieldref|startswith": "parent_process.file.path"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "startswith"
        assert pred.fieldref == "PARENT_PROCESS_FILE_PATH"

    def test_fieldref_with_endswith(self):
        rule = SigmaRule(
            id=1, description="fieldref endswith", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename|fieldref|endswith": "parent_process.file.filename"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "endswith"
        assert pred.fieldref == "PARENT_PROCESS_FILE_FILENAME"

    def test_fieldref_with_gt(self):
        rule = SigmaRule(
            id=1, description="fieldref gt", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref|gt": "parent_process.pid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "above"
        assert pred.fieldref == "PARENT_PROCESS_PID"

    def test_fieldref_with_gte(self):
        rule = SigmaRule(
            id=1, description="fieldref gte", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.euid|fieldref|gte": "parent_process.euid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "equal_above"
        assert pred.fieldref == "PARENT_PROCESS_EUID"

    def test_fieldref_with_lt(self):
        rule = SigmaRule(
            id=1, description="fieldref lt", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.rgid|fieldref|lt": "parent_process.rgid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "below"
        assert pred.fieldref == "PARENT_PROCESS_RGID"

    def test_fieldref_with_lte(self):
        rule = SigmaRule(
            id=1, description="fieldref lte", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref|lte": "parent_process.pid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "equal_below"
        assert pred.fieldref == "PARENT_PROCESS_PID"

    def test_fieldref_with_neq_creates_not(self):
        rule = SigmaRule(
            id=1, description="fieldref neq", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename|neq|fieldref": "parent_process.file.filename"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        assert child.operator_type == "PRED"
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "process.file.filename"
        assert pred.comparison_type == "exactmatch"
        assert pred.fieldref == "PARENT_PROCESS_FILE_FILENAME"

    def test_fieldref_gte_reversed_order(self):
        rule = SigmaRule(
            id=1, description="fieldref gte reversed", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.euid|gte|fieldref": "parent_process.euid"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.field == "process.euid"
        assert pred.comparison_type == "equal_above"
        assert pred.fieldref == "PARENT_PROCESS_EUID"

    def test_fieldref_deduplication(self):
        rule1 = SigmaRule(
            id=1, description="Rule 1", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref": "parent_process.pid"}, "condition": "sel"},
            source_file="rule1.yml"
        )
        rule2 = SigmaRule(
            id=2, description="Rule 2", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref": "parent_process.pid"}, "condition": "sel"},
            source_file="rule2.yml"
        )

        ctx = parse_rules([rule1, rule2])
        assert len(ctx.id_to_predicate) == 1
        assert len(ctx.id_to_string) == 0

    def test_fieldref_mixed_with_normal_fields(self):
        rule = SigmaRule(
            id=1, description="mixed fieldref", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {
                    "process.file.filename|fieldref": "parent_process.file.filename",
                    "process.cmd|contains": "suspicious",
                },
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        assert parsed.condition_expr.operator_type == "AND"
        assert len(parsed.condition_expr.children) == 2
        assert len(ctx.id_to_predicate) == 2
        assert len(ctx.id_to_string) == 1

        fieldref_preds = [p for p in ctx.id_to_predicate.values() if p.is_fieldref_predicate()]
        string_preds = [p for p in ctx.id_to_predicate.values() if p.is_string_predicate()]
        assert len(fieldref_preds) == 1
        assert len(string_preds) == 1

    def test_fieldref_full_pipeline(self):
        """fieldref goes through the full pipeline: load -> AST -> postfix -> serialize."""
        import json
        from postfix import convert_to_postfix
        from serializer import to_json_string

        rule = SigmaRule(
            id=1, description="fieldref pipeline", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {
                    "process.pid|fieldref|gte": "parent_process.pid",
                    "process.file.filename|fieldref": "parent_process.file.filename",
                },
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)

        assert len(data["rules"]) == 1
        assert len(data["id_to_predicate"]) == 2
        assert len(data["id_to_string"]) == 0

        preds = data["id_to_predicate"]
        fieldref_values = {p["fieldref"] for p in preds.values()}
        assert "PARENT_PROCESS_PID" in fieldref_values
        assert "PARENT_PROCESS_FILE_FILENAME" in fieldref_values

    def test_fieldref_duplicate_numeric_modifier_same_target_rejected(self):
        rule = SigmaRule(
            id=1, description="dup fieldref modifier", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {
                "process.pid|fieldref|gte": "parent_process.pid",
                "process.pid|fieldref|lt": "parent_process.pid",
            }, "condition": "sel"},
            source_file="test.yml"
        )
        with pytest.raises(Exception, match="[Dd]uplicate fieldref.*multiple.*numeric modifiers or string modifiers"):
            parse_rule_with_pysigma(rule, ParsedRulesContext())

    def test_fieldref_duplicate_string_modifier_same_target_rejected(self):
        rule = SigmaRule(
            id=1, description="dup string fieldref modifier", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {
                "process.file.path|fieldref|startswith": "process.file.filename",
                "process.file.path|fieldref|endswith": "process.file.filename",
            }, "condition": "sel"},
            source_file="test.yml"
        )
        with pytest.raises(Exception, match="[Dd]uplicate fieldref.*multiple.*numeric modifiers or string modifiers"):
            parse_rule_with_pysigma(rule, ParsedRulesContext())

    def test_fieldref_enum_neq_creates_not(self):
        rule = SigmaRule(
            id=1, description="fieldref enum neq", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.type|fieldref|neq": "parent_process.file.type"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]

        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "process.file.type"
        assert pred.comparison_type == "equal"
        assert pred.fieldref == "PARENT_PROCESS_FILE_TYPE"


class TestSimpleRuleParsing:
    """Tests for simple rule parsing."""
    
    def test_parse_single_selection(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename": "test.exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        assert parsed.rule_id == 1
        assert parsed.action == "BLOCK_EVENT"
        assert parsed.condition_expr.operator_type == "PRED"
        assert ctx.id_to_string[0].value == "test.exe"
        assert ctx.id_to_predicate[0].comparison_type == "exactmatch"


class TestModifiers:
    """Tests for string modifiers."""
    
    def test_contains_modifier(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "evil"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_predicate[0].comparison_type == "contains"
        assert ctx.id_to_string[0].string_type == StringType.CONTAINS
    
    def test_startswith_modifier(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"Path|startswith": "/usr/"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_predicate[0].comparison_type == "startswith"
        assert ctx.id_to_string[0].string_type == StringType.DEFAULT
    
    def test_endswith_modifier(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"Filename|endswith": ".exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_predicate[0].comparison_type == "endswith"


class TestWildcardsInAST:
    def test_multiple_internal_wildcards_raises(self):
        rule = SigmaRule(
            id=1, description="Multiple internal wildcards", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "test*val*ue"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        
        with pytest.raises(Exception, match="Two wildcards must be at start and end"):
            parse_rule_with_pysigma(rule, ctx)
    
    def test_single_char_wildcard_raises(self):
        rule = SigmaRule(
            id=1, description="Single char wildcard", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "prog?.exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        
        with pytest.raises(Exception, match="Single-character wildcard"):
            parse_rule_with_pysigma(rule, ctx)
    
    def test_internal_wildcard_creates_and(self):
        """Internal wildcard (val*ue) should create AND of startswith + endswith."""
        rule = SigmaRule(
            id=1, description="Internal wildcard", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "test*value"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # Should be an AND of two predicates
        assert parsed.condition_expr.operator_type == "AND"
        assert len(parsed.condition_expr.children) == 2
        
        # Check predicates
        pred1 = ctx.id_to_predicate[parsed.condition_expr.children[0].predicate_idx]
        pred2 = ctx.id_to_predicate[parsed.condition_expr.children[1].predicate_idx]
        
        assert pred1.comparison_type == "startswith"
        assert pred2.comparison_type == "endswith"
        assert ctx.id_to_string[pred1.string_idx].value == "test"
        assert ctx.id_to_string[pred2.string_idx].value == "value"
    
    def test_prefix_wildcard_creates_endswith(self):
        """Prefix wildcard (*value) should create endswith."""
        rule = SigmaRule(
            id=1, description="Prefix wildcard", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "*value"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "PRED"
        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "endswith"
        assert ctx.id_to_string[pred.string_idx].value == "value"
    
    def test_suffix_wildcard_creates_startswith(self):
        """Suffix wildcard (value*) should create startswith."""
        rule = SigmaRule(
            id=1, description="Suffix wildcard", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "value*"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "PRED"
        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "startswith"
        assert ctx.id_to_string[pred.string_idx].value == "value"
    
    def test_both_wildcards_creates_contains(self):
        """Both wildcards (*value*) should create contains."""
        rule = SigmaRule(
            id=1, description="Both wildcards", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": "*value*"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "PRED"
        pred = ctx.id_to_predicate[parsed.condition_expr.predicate_idx]
        assert pred.comparison_type == "contains"
        assert ctx.id_to_string[pred.string_idx].value == "value"


class TestEscapedCharacters:
    """Tests for escaped wildcard characters (literal * and ? in strings)."""
    
    def test_escaped_asterisk_becomes_literal(self):
        """Test that \\* in the value becomes a literal * character."""
        rule = SigmaRule(
            id=1, description="Escaped asterisk", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": r"test\*value"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        # Should parse successfully and contain literal asterisk
        assert ctx.id_to_string[0].value == "test*value"
        assert ctx.id_to_predicate[0].comparison_type == "exactmatch"
    
    def test_escaped_question_mark_becomes_literal(self):
        """Test that \\? in the value becomes a literal ? character."""
        rule = SigmaRule(
            id=1, description="Escaped question mark", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd": r"test\?value"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        # Should parse successfully and contain literal question mark
        assert ctx.id_to_string[0].value == "test?value"
        assert ctx.id_to_predicate[0].comparison_type == "exactmatch"
    
    def test_escaped_asterisk_and_question_mark_combined(self):
        """Test that both \\* and \\? can appear in the same string."""
        rule = SigmaRule(
            id=1, description="Both escaped", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"target.file.path": r"/tmp/escaped\*wildcards\?test"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_string[0].value == "/tmp/escaped*wildcards?test"
        assert ctx.id_to_predicate[0].comparison_type == "exactmatch"
    
    def test_double_backslash_becomes_single_backslash(self):
        """Test that \\\\ becomes a single backslash."""
        rule = SigmaRule(
            id=1, description="Double backslash", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.path": r"C:\\Windows\\System32"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_string[0].value == r"C:\Windows\System32"
    
    def test_escaped_asterisk_with_contains_modifier(self):
        """Test that escaped asterisk works with contains modifier."""
        rule = SigmaRule(
            id=1, description="Escaped with contains", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.cmd|contains": r"file\*name"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_string[0].value == "file*name"
        assert ctx.id_to_predicate[0].comparison_type == "contains"
    
    def test_backslash_before_normal_char_preserved(self):
        """Test that backslash before a normal character is preserved."""
        rule = SigmaRule(
            id=1, description="Backslash normal", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.path": r"/path/to\file"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)
        
        # Backslash before normal char is preserved as-is
        assert ctx.id_to_string[0].value == r"/path/to\file"


class TestNumericFields:
    """Tests for numeric field parsing."""
    
    def test_numeric_equal(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid": 1234}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        pred = ctx.id_to_predicate[0]
        assert pred.comparison_type == "equal"
        assert pred.numerical_value == 1234
        assert pred.is_numeric_predicate()
    
    def test_numeric_gt(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.euid|gt": 1000}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        assert ctx.id_to_predicate[0].comparison_type == "above"


class TestEnumFields:
    """Tests for enum field parsing."""
    
    def test_enum_converted_to_numeric(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.type": "REGULAR_FILE"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parse_rule_with_pysigma(rule, ctx)
        
        pred = ctx.id_to_predicate[0]
        assert pred.is_numeric_predicate()
        assert pred.numerical_value == 5  # REGULAR_FILE = 5


class TestConditions:
    """Tests for condition parsing."""
    
    def test_or_condition(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "a.exe"},
                "sel2": {"process.file.filename": "b.exe"},
                "condition": "sel1 or sel2"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "OR"
        assert len(parsed.condition_expr.children) == 2
    
    def test_and_condition(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "a.exe"},
                "sel2": {"process.file.path|contains": "temp"},
                "condition": "sel1 and sel2"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "AND"
    
    def test_not_condition(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"Path|startswith": "/usr/"},
                "condition": "not sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "NOT"
        assert parsed.condition_expr.children[0].operator_type == "PRED"
    
    def test_all_modifier_creates_and(self):
        rule = SigmaRule(
            id=1, description="Test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"CommandLine|contains|all": ["lsass", "-ma"]},
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "AND"
        assert len(parsed.condition_expr.children) == 2


class TestCrossRuleDeduplication:
    """Tests for deduplication across rules."""
    
    def test_strings_deduplicated_across_rules(self):
        rule1 = SigmaRule(
            id=1, description="Rule 1", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "lsass"}, "condition": "sel"},
            source_file="rule1.yml"
        )
        rule2 = SigmaRule(
            id=2, description="Rule 2", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "lsass"}, "condition": "sel"},
            source_file="rule2.yml"
        )
        
        ctx = parse_rules([rule1, rule2])
        
        assert len(ctx.id_to_string) == 1
        assert len(ctx.id_to_predicate) == 1
        assert ctx.rules[0].condition_expr.predicate_idx == ctx.rules[1].condition_expr.predicate_idx


class TestParseRulesIntegration:
    """Integration tests with actual rule files."""
    
    @pytest.fixture
    def valid_rules_dir(self):
        return os.path.join(os.path.dirname(__file__), 'valid_rules')
    
    def test_parse_all_rules(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ctx = parse_rules(rules)
        
        assert len(ctx.rules) == 31
        assert len(ctx.id_to_string) > 0
        assert len(ctx.id_to_predicate) > 0
    
    def test_all_rules_have_condition_expr(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ctx = parse_rules(rules)
        
        for rule in ctx.rules:
            assert rule.condition_expr is not None


class TestAllOfConditions:
    """Tests for 'all of' conditions."""
    
    def test_all_of_them(self):
        rule = SigmaRule(
            id=1, description="All of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "condition": "all of them"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "AND"
        assert len(parsed.condition_expr.children) == 3
    
    def test_1_of_them(self):
        rule = SigmaRule(
            id=1, description="1 of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "condition": "1 of them"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "OR"
        assert len(parsed.condition_expr.children) == 3


class TestXOfConditions:
    """Tests for 'X of' conditions."""
    
    def test_2_of_them(self):
        rule = SigmaRule(
            id=1, description="2 of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "condition": "2 of them"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # 2 of 3 creates OR of 3 combinations
        assert parsed.condition_expr.operator_type == "OR"
        assert len(parsed.condition_expr.children) == 3
        
        for child in parsed.condition_expr.children:
            assert child.operator_type == "AND"
            assert len(child.children) == 2
    
    def test_3_of_4(self):
        rule = SigmaRule(
            id=1, description="3 of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "sel4": {"process.file.filename": "test4.exe"},
                "condition": "3 of them"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # C(4,3) = 4 combinations
        assert parsed.condition_expr.operator_type == "OR"
        assert len(parsed.condition_expr.children) == 4


class TestConditionExprRepr:
    """Tests for ConditionExpr string representation."""
    
    def test_pred_repr(self):
        expr = ConditionExpr(operator_type="PRED", predicate_idx=5)
        assert repr(expr) == "PRED(5)"
    
    def test_not_repr(self):
        expr = ConditionExpr(operator_type="NOT", children=[ConditionExpr(operator_type="PRED", predicate_idx=3)])
        assert "NOT" in repr(expr)
        assert "PRED(3)" in repr(expr)


class TestMaxTotalPreds:
    """Tests for MAX_TOTAL_PREDS limit."""
    
    def test_max_preds_allowed(self):
        ctx = ParsedRulesContext()
        for i in range(MAX_TOTAL_PREDS):
            pred = Predicate(field="process.pid", comparison_type="equal", numerical_value=i)
            ctx.get_or_add_predicate(pred)
        assert len(ctx.id_to_predicate) == MAX_TOTAL_PREDS
    
    def test_exceeding_max_preds_raises(self):
        ctx = ParsedRulesContext()
        for i in range(MAX_TOTAL_PREDS):
            pred = Predicate(field="process.pid", comparison_type="equal", numerical_value=i)
            ctx.get_or_add_predicate(pred)
        
        with pytest.raises(ValueError, match=f"Exceeded maximum number of predicates \\({MAX_TOTAL_PREDS}\\)"):
            pred = Predicate(field="process.pid", comparison_type="equal", numerical_value=MAX_TOTAL_PREDS)
            ctx.get_or_add_predicate(pred)


class TestKeywordBackend:
    """Tests for keyword expansion in the backend."""
    
    def test_keyword_single_event_expands_to_or(self):
        """Keyword with single event should expand to OR of all string fields."""
        rule = SigmaRule(
            id=1, description="Keyword test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"keywords": ["malware"], "condition": "keywords"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        assert parsed.applied_events == ["CHMOD"]
        # Should be OR of multiple predicates (one per string field)
        assert parsed.condition_expr.operator_type == "OR"
        # CHMOD has 10 string fields (process.*, parent_process.* incl. shell_command, target.file.*)
        assert len(parsed.condition_expr.children) == 10
    
    def test_keyword_multiple_events_creates_separate_rules(self):
        """Keyword with multiple events should create separate ParsedRules."""
        rule = SigmaRule(
            id=1, description="Multi-event keyword", action="BLOCK_EVENT", events=["CHMOD", "EXEC"],
            detection={"keywords": ["malware"], "condition": "keywords"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 2
        
        # Both should have same ID but different events
        assert parsed_list[0].rule_id == 1
        assert parsed_list[1].rule_id == 1
        assert parsed_list[0].applied_events == ["CHMOD"]
        assert parsed_list[1].applied_events == ["EXEC"]
        
        # CHMOD has 10 string fields, EXEC has 12 string fields (incl. shell_command)
        chmod_children = len(parsed_list[0].condition_expr.children)
        exec_children = len(parsed_list[1].condition_expr.children)
        assert chmod_children == 10
        assert exec_children == 12
    
    def test_keyword_with_all_modifier_creates_and(self):
        """Keyword with |all modifier should create AND of OR predicates."""
        rule = SigmaRule(
            id=1, description="Keyword all test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "keywords": {"'|all'": ["must1", "must2"]},
                "condition": "keywords"
            },
            source_file="test.yml"
        )
        # Note: The |all modifier is handled by pySigma, which creates AND of the keyword values
        # We test that our backend correctly processes this
        ctx = ParsedRulesContext()
        # Need to use actual yaml-like detection format
        rule_yaml = SigmaRule(
            id=1, description="Keyword all test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "keywords": {"|all": ["must1", "must2"]},
                "condition": "keywords"
            },
            source_file="test.yml"
        )
        parsed_list = parse_rule_with_pysigma(rule_yaml, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        # With |all, it should be AND of two ORs
        assert parsed.condition_expr.operator_type == "AND"
        assert len(parsed.condition_expr.children) == 2
        # Each child should be OR of string fields
        for child in parsed.condition_expr.children:
            assert child.operator_type == "OR"
    
    def test_keyword_with_wildcard(self):
        """Keyword with wildcard should be converted correctly."""
        rule = SigmaRule(
            id=1, description="Keyword wildcard test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"keywords": ["*malware*"], "condition": "keywords"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        assert parsed.condition_expr.operator_type == "OR"
        # All predicates should be "contains" type
        for child in parsed.condition_expr.children:
            pred = ctx.id_to_predicate[child.predicate_idx]
            assert pred.comparison_type == "contains"
    
    def test_keyword_mixed_with_field_selection(self):
        """Keywords can be mixed with field-based selections."""
        rule = SigmaRule(
            id=1, description="Mixed test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "keywords": ["malware"],
                "field_sel": {"process.pid|gt": 1000},
                "condition": "keywords and field_sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        # Should be AND of keywords OR and field predicate
        assert parsed.condition_expr.operator_type == "AND"
    
    def test_no_keywords_single_rule_returned(self):
        """Rule without keywords should return single ParsedRule."""
        rule = SigmaRule(
            id=1, description="No keywords", action="BLOCK_EVENT", events=["CHMOD", "EXEC"],
            detection={"sel": {"process.cmd|contains": "test"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        assert parsed_list[0].applied_events == ["CHMOD", "EXEC"]
    
    def test_keyword_rename_event_fields(self):
        """Keyword with RENAME event should include rename-specific fields."""
        rule = SigmaRule(
            id=1, description="Rename keyword", action="BLOCK_EVENT", events=["RENAME"],
            detection={"keywords": ["malware"], "condition": "keywords"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        # RENAME has 8 common + 4 rename = 12 string fields (incl. shell_command)
        assert len(parsed.condition_expr.children) == 12
    
    def test_keyword_exec_event_fields(self):
        """Keyword with EXEC event should include target.process fields."""
        rule = SigmaRule(
            id=1, description="Exec keyword", action="BLOCK_EVENT", events=["EXEC"],
            detection={"keywords": ["malware"], "condition": "keywords"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed_list = parse_rule_with_pysigma(rule, ctx)
        
        assert len(parsed_list) == 1
        parsed = parsed_list[0]
        # EXEC has 8 common + 4 target.process = 12 string fields (incl. shell_command)
        assert len(parsed.condition_expr.children) == 12


class TestNeqModifier:
    """Tests for |neq modifier processing through the AST pipeline."""
    
    def test_neq_string_creates_not_predicate(self):
        """neq on a string field wraps the predicate in NOT."""
        rule = SigmaRule(
            id=1, description="neq string", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename|neq": "bad.exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        assert child.operator_type == "PRED"
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "process.file.filename"
        assert pred.comparison_type == "exactmatch"
        assert ctx.id_to_string[pred.string_idx].value == "bad.exe"
    
    def test_neq_numeric_creates_not_predicate(self):
        """neq on a numeric field wraps the predicate in NOT."""
        rule = SigmaRule(
            id=1, description="neq numeric", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|neq": 100}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        assert child.operator_type == "PRED"
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "process.pid"
        assert pred.comparison_type == "equal"
        assert pred.numerical_value == 100
    
    def test_neq_enum_creates_not_predicate(self):
        """neq on an enum field wraps the predicate in NOT."""
        rule = SigmaRule(
            id=1, description="neq enum", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.type|neq": "REGULAR_FILE"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        assert child.operator_type == "PRED"
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "process.file.type"
        assert pred.comparison_type == "equal"
        assert pred.numerical_value == 5  # REGULAR_FILE = 5
    
    def test_neq_mixed_with_normal_fields(self):
        """neq combined with normal fields: sel becomes AND(normal_pred, NOT(neq_pred))."""
        rule = SigmaRule(
            id=1, description="mixed neq", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {
                    "process.file.path|startswith": "/usr/bin/",
                    "process.pid|neq": 1,
                },
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # Should be AND(startswith_pred, NOT(equal_pred))
        assert parsed.condition_expr.operator_type == "AND"
        children = parsed.condition_expr.children
        assert len(children) == 2
        
        # One child is a PRED, one is a NOT
        types = {c.operator_type for c in children}
        assert "PRED" in types
        assert "NOT" in types
    
    def test_neq_only_selection_replaces_in_condition(self):
        """A selection with only neq fields should replace sel with NOT in condition."""
        rule = SigmaRule(
            id=1, description="neq only", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"process.pid|neq": 0},
                "other": {"process.cmd|contains": "test"},
                "condition": "sel and other"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # Outer should be AND
        assert parsed.condition_expr.operator_type == "AND"
        children = parsed.condition_expr.children
        types = {c.operator_type for c in children}
        assert "NOT" in types
        assert "PRED" in types
    
    def test_neq_multiple_fields_in_selection(self):
        """Multiple neq fields in one selection create multiple NOT clauses."""
        rule = SigmaRule(
            id=1, description="multi neq", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {
                    "process.pid|neq": 0,
                    "process.euid|neq": 1000,
                },
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        # Both neq fields create NOTs, ANDed together
        assert parsed.condition_expr.operator_type == "AND"
        for child in parsed.condition_expr.children:
            assert child.operator_type == "NOT"
    
    def test_neq_string_list_rejected(self):
        """neq with a list of string values should be rejected."""
        rule = SigmaRule(
            id=1, description="neq list", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"process.file.filename|neq": ["bash", "sh"]},
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            parse_rule_with_pysigma(rule, ctx)
    
    def test_neq_numeric_list_rejected(self):
        """neq with a list of numeric values should be rejected."""
        rule = SigmaRule(
            id=1, description="neq numeric list", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"process.pid|neq": [0, 1]},
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            parse_rule_with_pysigma(rule, ctx)
    
    def test_neq_dict_value_rejected(self):
        """neq with a dict value should be rejected."""
        rule = SigmaRule(
            id=1, description="neq dict", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {"process.file.filename|neq": {"key": "value"}},
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        
        with pytest.raises(Exception, match="neq.*only supports a single scalar"):
            parse_rule_with_pysigma(rule, ctx)
    
    def test_neq_ip_creates_not_predicate(self):
        """neq on an IP field wraps the predicate in NOT."""
        rule = SigmaRule(
            id=1, description="neq ip", action="BLOCK_EVENT", events=["NETWORK"],
            detection={"sel": {"network.source_ip|neq": "192.168.1.1"}, "condition": "sel"},
            source_file="test.yml"
        )
        ctx = ParsedRulesContext()
        parsed = parse_rule_with_pysigma(rule, ctx)[0]
        
        assert parsed.condition_expr.operator_type == "NOT"
        child = parsed.condition_expr.children[0]
        assert child.operator_type == "PRED"
        pred = ctx.id_to_predicate[child.predicate_idx]
        assert pred.field == "network.source_ip"
        assert pred.comparison_type == "equal"
        ip_entry = ctx.id_to_ip[pred.numerical_value]
        assert ip_entry.ip == "192.168.1.1"
        assert ip_entry.cidr == 32
    
    def test_neq_full_pipeline_postfix(self):
        """neq goes through the full pipeline: load -> AST -> postfix -> serialize."""
        import json
        from postfix import convert_to_postfix
        from serializer import to_json_string
        from constants import OperatorType
        
        rule = SigmaRule(
            id=1, description="neq pipeline", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel": {
                    "target.file.path|startswith": "/tmp/",
                    "chmod.requested_mode|neq": 493,
                },
                "condition": "sel"
            },
            source_file="test.yml"
        )
        ctx = parse_rules([rule])
        
        postfix_ctx = convert_to_postfix(ctx)
        json_str = to_json_string(postfix_ctx)
        data = json.loads(json_str)
        
        # Rule should exist and have tokens including NOT
        assert len(data["rules"]) == 1
        tokens = data["rules"][0]["tokens"]
        token_types = [t["operator_type"] for t in tokens]
        assert OperatorType.OPERATOR_NOT.value in token_types
        assert OperatorType.OPERATOR_AND.value in token_types


class TestGetStringFieldsForEvent:
    """Tests for get_string_fields_for_event function."""
    
    def test_always_includes_common_fields(self):
        """All event types should include process and parent_process string fields."""
        for event_type in ["CHMOD", "EXEC", "RENAME", "CHOWN", "LINK", "SYMLINK"]:
            fields = get_string_fields_for_event(event_type)
            assert "process.cmd" in fields
            assert "process.shell_command" in fields
            assert "process.file.path" in fields
            assert "process.file.filename" in fields
            assert "parent_process.cmd" in fields
            assert "parent_process.shell_command" in fields
            assert "parent_process.file.path" in fields
            assert "parent_process.file.filename" in fields
    
    def test_chmod_includes_target_file_fields(self):
        """CHMOD event should include target.file string fields."""
        fields = get_string_fields_for_event("CHMOD")
        assert "target.file.path" in fields
        assert "target.file.filename" in fields
    
    def test_exec_includes_target_process_fields(self):
        """EXEC event should include target.process string fields."""
        fields = get_string_fields_for_event("EXEC")
        assert "target.process.cmd" in fields
        assert "target.process.shell_command" in fields
        assert "target.process.file.path" in fields
        assert "target.process.file.filename" in fields
    
    def test_rename_includes_rename_fields(self):
        """RENAME event should include rename-specific string fields."""
        fields = get_string_fields_for_event("RENAME")
        assert "rename.source_file.path" in fields
        assert "rename.source_file.filename" in fields
        assert "rename.destination_file.path" in fields
        assert "rename.destination_file.filename" in fields
    
    def test_file_events_have_same_target_fields(self):
        """File events in EVENT_ALLOWED_TARGET_FIELDS should have target.file fields."""
        file_events = ["CHMOD", "CHOWN", "UNLINK"]
        base_fields = get_string_fields_for_event("CHMOD")
        for event_type in file_events:
            assert get_string_fields_for_event(event_type) == base_fields
    
    def test_excludes_numeric_fields(self):
        """Should not include numeric fields like pid, uid, etc."""
        fields = get_string_fields_for_event("CHMOD")
        assert "process.pid" not in fields
        assert "process.uid" not in fields
        assert "target.file.mode" not in fields
    
    def test_unknown_event_returns_only_common(self):
        """Unknown event type should return only common fields."""
        fields = get_string_fields_for_event("UNKNOWN_EVENT")
        assert len(fields) == 8  # 8 common string fields (incl. shell_command)
        assert "process.cmd" in fields
        assert "process.shell_command" in fields
        assert "target.file.path" not in fields
