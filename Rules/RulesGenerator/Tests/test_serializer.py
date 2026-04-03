"""Test suite for serializer module."""
import os
import json
import pytest

from sigma_rule_loader import load_sigma_rules, SigmaRule
from AST import parse_rules, Predicate
from postfix import convert_to_postfix, Token, OperatorType, PostfixRule, PostfixRulesContext
from serializer import serialize_context
from constants import StringType


class TestBasicSerialization:
    """Tests for basic JSON serialization."""
    
    def test_serialize_structure(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "evil"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        assert "id_to_string" in data
        assert "id_to_predicate" in data
        assert "rules" in data
    
    def test_strings_serialized_correctly(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "test_value"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        # id_to_string is a dict with string keys
        string_entry = data["id_to_string"]["0"]
        assert string_entry["value"] == "test_value"
        assert string_entry["string_type"] == StringType.CONTAINS.value
    
    def test_preds_serialized_correctly(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename": "test.exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        pred = data["id_to_predicate"]["0"]
        assert pred["field"] == "process.file.filename"
        assert pred["comparison_type"] == "exactmatch"
        assert "string_idx" in pred
        assert pred["fieldref"] == "FIELD_TYPE_NONE"
    
    def test_numeric_pred_serialization(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.euid|gt": 1000}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        pred = data["id_to_predicate"]["0"]
        assert pred["field"] == "process.euid"
        assert pred["comparison_type"] == "above"
        assert pred["numerical_value"] == 1000
        # -1 indicates no string_idx for numeric predicates
        assert pred["string_idx"] == -1
        assert pred["fieldref"] == "FIELD_TYPE_NONE"


class TestFieldrefSerialization:
    """Tests for fieldref predicate serialization."""

    def test_fieldref_pred_serialization(self):
        rule = SigmaRule(
            id=1, description="fieldref test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.pid|fieldref": "parent_process.pid"}, "condition": "sel"},
            source_file="test.yml"
        )

        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)

        pred = data["id_to_predicate"]["0"]
        assert pred["field"] == "process.pid"
        assert pred["comparison_type"] == "equal"
        assert pred["fieldref"] == "PARENT_PROCESS_PID"
        assert pred["string_idx"] == -1
        assert pred["numerical_value"] == -1

    def test_fieldref_string_with_startswith(self):
        rule = SigmaRule(
            id=1, description="fieldref startswith", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.path|fieldref|startswith": "parent_process.file.path"}, "condition": "sel"},
            source_file="test.yml"
        )

        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)

        pred = data["id_to_predicate"]["0"]
        assert pred["comparison_type"] == "startswith"
        assert pred["fieldref"] == "PARENT_PROCESS_FILE_PATH"

    def test_fieldref_numeric_with_gte(self):
        rule = SigmaRule(
            id=1, description="fieldref gte", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.euid|fieldref|gte": "parent_process.euid"}, "condition": "sel"},
            source_file="test.yml"
        )

        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)

        pred = data["id_to_predicate"]["0"]
        assert pred["comparison_type"] == "equal_above"
        assert pred["fieldref"] == "PARENT_PROCESS_EUID"


class TestRuleSerialization:
    """Tests for rule serialization."""
    
    def test_rule_metadata(self):
        rule = SigmaRule(
            id=42, description="Test description", action="KILL_PROCESS", events=["CHMOD", "READ"],
            detection={"sel": {"process.file.filename": "test.exe"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        rule_data = data["rules"][0]
        assert rule_data["id"] == 42
        assert rule_data["action"] == "KILL_PROCESS"
        assert rule_data["description"] == "Test description"
        assert set(rule_data["applied_events"]) == {"CHMOD", "READ"}
    
    def test_tokens_serialized(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "a.exe"},
                "sel2": {"process.file.filename": "b.exe"},
                "condition": "sel1 and sel2"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        tokens = data["rules"][0]["tokens"]
        assert len(tokens) == 3
        
        ops = [t["operator_type"] for t in tokens]
        assert ops == ["OPERATOR_PREDICATE", "OPERATOR_PREDICATE", "OPERATOR_AND"]


class TestMultipleRules:
    """Tests for multiple rule serialization."""
    
    def test_string_deduplication_in_output(self):
        rule1 = SigmaRule(
            id=1, description="Rule 1", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "shared_value"}, "condition": "sel"},
            source_file="rule1.yml"
        )
        rule2 = SigmaRule(
            id=2, description="Rule 2", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": "shared_value"}, "condition": "sel"},
            source_file="rule2.yml"
        )
        
        ast_ctx = parse_rules([rule1, rule2])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        assert len(data["id_to_string"]) == 1
        assert len(data["id_to_predicate"]) == 1
        assert len(data["rules"]) == 2


class TestFullPipelineIntegration:
    """Integration tests with actual rule files."""
    
    @pytest.fixture
    def valid_rules_dir(self):
        return os.path.join(os.path.dirname(__file__), 'valid_rules')
    
    def test_pipeline_with_test_files(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        assert len(data["rules"]) == 31
        
        for rule in data["rules"]:
            assert "id" in rule
            assert "action" in rule
            assert "tokens" in rule
            assert "applied_events" in rule
            assert len(rule["tokens"]) > 0
    
    def test_json_serializable(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        # Should not raise - data should be JSON serializable
        json_str = json.dumps(data, indent=2)
        data2 = json.loads(json_str)
        assert data == data2


class TestOperatorTypeSerialization:
    """Tests for operation code serialization."""
    
    def test_all_operator_types_serializable(self):
        # Create rule with all operations
        rule = SigmaRule(
            id=1, description="All ops", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "a.exe"},
                "sel2": {"process.file.filename": "b.exe"},
                "filter": {"process.file.path|startswith": "/usr/"},
                "condition": "(sel1 or sel2) and not filter"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        ops = {t["operator_type"] for t in data["rules"][0]["tokens"]}
        assert "OPERATOR_PREDICATE" in ops
        assert "OPERATOR_AND" in ops
        assert "OPERATOR_OR" in ops
        assert "OPERATOR_NOT" in ops


class TestOutputConsistency:
    """Tests for output consistency."""
    
    def test_deterministic_output(self):
        rule = SigmaRule(
            id=1, description="Determinism test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "a.exe"},
                "sel2": {"Path|contains": "temp"},
                "condition": "sel1 or sel2"
            },
            source_file="test.yml"
        )
        
        outputs = []
        for _ in range(3):
            ast_ctx = parse_rules([rule])
            postfix_ctx = convert_to_postfix(ast_ctx)
            outputs.append(json.dumps(serialize_context(postfix_ctx), sort_keys=True))
        
        assert outputs[0] == outputs[1] == outputs[2]


class TestAppliedEvents:
    """Tests for applied_events serialization."""
    
    def test_single_event(self):
        rule = SigmaRule(
            id=1, description="Single event", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"process.file.filename": "test"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        assert data["rules"][0]["applied_events"] == ["CHMOD"]
    
    def test_multiple_events(self):
        rule = SigmaRule(
            id=1, description="Multiple events", action="BLOCK_EVENT",
            events=["CHMOD", "READ", "WRITE"],
            detection={"sel": {"process.file.filename": "test"}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        data = serialize_context(postfix_ctx)
        
        assert set(data["rules"][0]["applied_events"]) == {"CHMOD", "READ", "WRITE"}
