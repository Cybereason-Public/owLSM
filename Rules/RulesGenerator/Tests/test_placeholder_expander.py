"""Comprehensive tests for the placeholder expansion feature.

Tests cover:
- Placeholder file loading and validation
- Detection dict expansion with |expand modifier
- Combination with |contains, |startswith, |endswith modifiers
- Combination with |all modifier
- Error handling for missing/invalid placeholders
- E2E: rules with placeholders through the full pipeline
- Ensuring %value% without |expand is treated literally
"""
import json
import pytest
from placeholder_expander import (
    load_placeholders,
    expand_detection_placeholders,
    _parse_placeholder_name,
    _has_expand_modifier,
    _remove_expand_modifier,
)
from sigma_rule_loader import load_sigma_rules, SigmaRule
from AST import parse_rules
from postfix import convert_to_postfix
from serializer import serialize_context, to_json_string


# =============================================================================
# 1) Placeholder File Loading
# =============================================================================

class TestLoadPlaceholders:

    def test_load_valid_file(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("shells:\n  - bash\n  - zsh\n")
        result = load_placeholders(str(ph_file))
        assert result == {"shells": ["bash", "zsh"]}

    def test_load_multiple_placeholders(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text(
            "shells:\n  - bash\n  - zsh\n"
            "paths:\n  - /tmp/\n  - /var/tmp/\n"
        )
        result = load_placeholders(str(ph_file))
        assert len(result) == 2
        assert result["shells"] == ["bash", "zsh"]
        assert result["paths"] == ["/tmp/", "/var/tmp/"]

    def test_load_numeric_values(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("thresholds:\n  - 100\n  - 200\n")
        result = load_placeholders(str(ph_file))
        assert result["thresholds"] == [100, 200]

    def test_load_mixed_string_and_numeric(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("mixed:\n  - hello\n  - 42\n")
        result = load_placeholders(str(ph_file))
        assert result["mixed"] == ["hello", 42]

    def test_empty_file_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("")
        with pytest.raises(Exception, match="empty"):
            load_placeholders(str(ph_file))

    def test_non_dict_root_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("- item1\n- item2\n")
        with pytest.raises(Exception, match="mapping"):
            load_placeholders(str(ph_file))

    def test_empty_list_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("shells: []\n")
        with pytest.raises(Exception, match="at least one value"):
            load_placeholders(str(ph_file))

    def test_non_list_value_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("shells: bash\n")
        with pytest.raises(Exception, match="list"):
            load_placeholders(str(ph_file))

    def test_invalid_value_type_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("shells:\n  - [nested, list]\n")
        with pytest.raises(Exception, match="strings or numbers"):
            load_placeholders(str(ph_file))

    def test_nonexistent_file_raises(self):
        with pytest.raises(Exception, match="Failed to read"):
            load_placeholders("/nonexistent/path.yml")

    def test_invalid_yaml_raises(self, tmp_path):
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text(":\n  invalid: yaml: content: [")
        with pytest.raises(Exception):
            load_placeholders(str(ph_file))


# =============================================================================
# 2) Placeholder Name Parsing (using pySigma)
# =============================================================================

class TestParsePlaceholderName:

    def test_simple_placeholder(self):
        assert _parse_placeholder_name("%shell_names%") == "shell_names"

    def test_placeholder_with_spaces_not_parsed(self):
        """pySigma's placeholder syntax does not allow spaces inside %...%."""
        assert _parse_placeholder_name("% shell_names %") is None

    def test_not_a_placeholder_no_percent(self):
        assert _parse_placeholder_name("shell_names") is None

    def test_not_a_placeholder_single_percent(self):
        assert _parse_placeholder_name("%shell_names") is None

    def test_not_a_placeholder_mixed_text(self):
        assert _parse_placeholder_name("prefix_%name%_suffix") is None

    def test_non_string_returns_none(self):
        assert _parse_placeholder_name(42) is None

    def test_empty_string_returns_none(self):
        assert _parse_placeholder_name("") is None

    def test_literal_percent_value(self):
        assert _parse_placeholder_name("100%") is None


# =============================================================================
# 3) Expand Modifier Detection
# =============================================================================

class TestExpandModifierDetection:

    def test_has_expand(self):
        assert _has_expand_modifier("field|expand") is True

    def test_has_expand_with_other_modifiers(self):
        assert _has_expand_modifier("field|contains|expand") is True

    def test_has_expand_all(self):
        assert _has_expand_modifier("field|expand|all") is True

    def test_no_expand(self):
        assert _has_expand_modifier("field|contains") is False

    def test_no_modifiers(self):
        assert _has_expand_modifier("field") is False

    def test_remove_expand_only(self):
        assert _remove_expand_modifier("field|expand") == "field"

    def test_remove_expand_keeps_others(self):
        assert _remove_expand_modifier("field|contains|expand") == "field|contains"

    def test_remove_expand_keeps_all(self):
        assert _remove_expand_modifier("field|expand|all") == "field|all"

    def test_remove_expand_from_triple(self):
        assert _remove_expand_modifier("field|contains|expand|all") == "field|contains|all"


# =============================================================================
# 4) Detection Dict Expansion
# =============================================================================

PLACEHOLDERS = {
    "shells": ["bash", "zsh", "fish"],
    "paths": ["/tmp/", "/var/tmp/"],
    "keywords": ["sudo", "admin"],
}


class TestExpandDetection:

    def test_simple_expand(self):
        detection = {
            "sel": {"process.file.filename|expand": "%shells%"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"] == {"process.file.filename": ["bash", "zsh", "fish"]}
        assert result["condition"] == "sel"

    def test_expand_with_contains(self):
        detection = {
            "sel": {"target.file.path|contains|expand": "%paths%"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"] == {"target.file.path|contains": ["/tmp/", "/var/tmp/"]}

    def test_expand_with_startswith(self):
        detection = {
            "sel": {"target.file.path|startswith|expand": "%paths%"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"] == {"target.file.path|startswith": ["/tmp/", "/var/tmp/"]}

    def test_expand_with_endswith(self):
        detection = {
            "sel": {"process.file.filename|endswith|expand": "%shells%"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"] == {"process.file.filename|endswith": ["bash", "zsh", "fish"]}

    def test_expand_with_all(self):
        detection = {
            "sel": {"process.cmd|contains|expand|all": "%keywords%"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"] == {"process.cmd|contains|all": ["sudo", "admin"]}

    def test_expand_preserves_non_expand_fields(self):
        detection = {
            "sel": {
                "process.file.filename|expand": "%shells%",
                "process.pid|gt": 100,
            },
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"]["process.file.filename"] == ["bash", "zsh", "fish"]
        assert result["sel"]["process.pid|gt"] == 100

    def test_expand_multiple_fields_in_selection(self):
        detection = {
            "sel": {
                "process.file.filename|expand": "%shells%",
                "target.file.path|contains|expand": "%paths%",
            },
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"]["process.file.filename"] == ["bash", "zsh", "fish"]
        assert result["sel"]["target.file.path|contains"] == ["/tmp/", "/var/tmp/"]

    def test_expand_in_list_of_dicts(self):
        detection = {
            "sel": [
                {"process.file.filename|expand": "%shells%"},
                {"process.cmd|contains": "test"},
            ],
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"][0] == {"process.file.filename": ["bash", "zsh", "fish"]}
        assert result["sel"][1] == {"process.cmd|contains": "test"}

    def test_expand_list_value_with_placeholder(self):
        """A list value where one entry is a placeholder and another is literal."""
        detection = {
            "sel": {"process.file.filename|expand": ["%shells%", "custom_shell"]},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"]["process.file.filename"] == ["bash", "zsh", "fish", "custom_shell"]

    def test_expand_list_value_with_multiple_placeholders(self):
        detection = {
            "sel": {"process.file.filename|expand": ["%shells%", "%keywords%"]},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result["sel"]["process.file.filename"] == ["bash", "zsh", "fish", "sudo", "admin"]

    def test_no_expand_modifier_passes_through(self):
        detection = {
            "sel": {"process.file.filename": "test"},
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result == detection

    def test_keyword_selection_passes_through(self):
        detection = {
            "sel": ["keyword1", "keyword2"],
            "condition": "sel",
        }
        result = expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")
        assert result == detection


# =============================================================================
# 5) Error Handling
# =============================================================================

class TestExpandErrors:

    def test_unknown_placeholder_raises(self):
        detection = {
            "sel": {"process.file.filename|expand": "%nonexistent%"},
            "condition": "sel",
        }
        with pytest.raises(Exception, match="Unknown placeholder"):
            expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")

    def test_expand_without_placeholders_provided_raises(self):
        detection = {
            "sel": {"process.file.filename|expand": "%shells%"},
            "condition": "sel",
        }
        with pytest.raises(Exception, match="no placeholder file was provided"):
            expand_detection_placeholders(detection, None, "test.yml")

    def test_expand_with_empty_placeholders_raises(self):
        detection = {
            "sel": {"process.file.filename|expand": "%shells%"},
            "condition": "sel",
        }
        with pytest.raises(Exception, match="no placeholder file was provided"):
            expand_detection_placeholders(detection, {}, "test.yml")

    def test_unknown_placeholder_in_list_raises(self):
        detection = {
            "sel": {"process.file.filename|expand": ["%shells%", "%missing%"]},
            "condition": "sel",
        }
        with pytest.raises(Exception, match="Unknown placeholder"):
            expand_detection_placeholders(detection, PLACEHOLDERS, "test.yml")


# =============================================================================
# 6) Percent-Value Without |expand Stays Literal
# =============================================================================

class TestPercentLiteralWithoutExpand:
    """Ensure that %value% in non-expand fields is treated as a literal string."""

    def test_percent_value_in_string_field_is_literal(self, tmp_path):
        rule = """
id: 300
description: "Rule with literal percent value"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "%not_a_placeholder%"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "%not_a_placeholder%" in string_values

    def test_percent_value_in_list_is_literal(self, tmp_path):
        rule = """
id: 301
description: "Rule with literal percent value in list"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: ["%value1%", "%value2%"]
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "%value1%" in string_values
        assert "%value2%" in string_values

    def test_percent_value_with_contains_is_literal(self, tmp_path):
        rule = """
id: 302
description: "Rule with literal percent in contains"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|contains: "%literal%"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "%literal%" in string_values


# =============================================================================
# 7) E2E: Full Pipeline With Placeholders
# =============================================================================

class TestPlaceholderE2E:

    def _write_rule_and_placeholders(self, tmp_path, rule_text, ph_text):
        (tmp_path / "rule.yml").write_text(rule_text)
        ph_file = tmp_path / "placeholders.yml"
        ph_file.write_text(ph_text)
        return str(ph_file)

    def test_simple_expand_e2e(self, tmp_path):
        rule = """
id: 400
description: "Expand shell names"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%shells%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(tmp_path, rule, "shells:\n  - bash\n  - zsh\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        assert len(rules) == 1
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "bash" in string_values
        assert "zsh" in string_values

    def test_expand_with_contains_e2e(self, tmp_path):
        rule = """
id: 401
description: "Expand paths with contains"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        target.file.path|contains|expand: "%paths%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "paths:\n  - /tmp/\n  - /var/tmp/\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "/tmp/" in string_values
        assert "/var/tmp/" in string_values

        from constants import StringType
        for entry in ctx.id_to_string.values():
            assert entry.string_type == StringType.CONTAINS

    def test_expand_with_all_modifier_e2e(self, tmp_path):
        """expand + all: all expanded values must match (AND)."""
        rule = """
id: 402
description: "Expand keywords with all modifier"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.cmd|contains|expand|all: "%kw%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "kw:\n  - sudo\n  - admin\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "sudo" in string_values
        assert "admin" in string_values

        condition = ctx.rules[0].condition_expr
        assert condition.operator_type == "AND"

    def test_expand_with_startswith_e2e(self, tmp_path):
        rule = """
id: 403
description: "Expand with startswith"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.path|startswith|expand: "%prefixes%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "prefixes:\n  - /usr/bin/\n  - /opt/\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "/usr/bin/" in string_values
        assert "/opt/" in string_values

        preds = list(ctx.id_to_predicate.values())
        for pred in preds:
            assert pred.comparison_type == "startswith"

    def test_expand_with_endswith_e2e(self, tmp_path):
        rule = """
id: 404
description: "Expand with endswith"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|endswith|expand: "%suffixes%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "suffixes:\n  - .sh\n  - .py\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert ".sh" in string_values
        assert ".py" in string_values

        preds = list(ctx.id_to_predicate.values())
        for pred in preds:
            assert pred.comparison_type == "endswith"

    def test_expand_produces_or_condition(self, tmp_path):
        """Multiple expanded values without |all should produce OR."""
        rule = """
id: 405
description: "Expand without all produces OR"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%shells%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n  - fish\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        condition = ctx.rules[0].condition_expr
        assert condition.operator_type == "OR"
        assert len(condition.children) == 3

    def test_single_value_expand_no_or(self, tmp_path):
        """A placeholder with a single value should not produce OR."""
        rule = """
id: 406
description: "Single value expand"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%single%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "single:\n  - only_one\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        condition = ctx.rules[0].condition_expr
        assert condition.operator_type == "PRED"

    def test_expand_mixed_with_normal_fields(self, tmp_path):
        rule = """
id: 407
description: "Expand mixed with normal fields"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%shells%"
        process.pid|gt: 100
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "bash" in string_values
        assert "zsh" in string_values

    def test_expand_in_complex_condition(self, tmp_path):
        rule = """
id: 408
description: "Complex condition with expand"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel_shell:
        process.file.filename|expand: "%shells%"
    sel_path:
        target.file.path|startswith: "/etc/"
    condition: sel_shell and sel_path
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ctx)
        data = serialize_context(postfix_ctx)

        assert len(data["rules"]) == 1
        string_values = {entry["value"] for entry in data["id_to_string"].values()}
        assert "bash" in string_values
        assert "zsh" in string_values
        assert "/etc/" in string_values

    def test_placeholder_file_in_rules_dir_excluded(self, tmp_path):
        """Placeholder file inside the rules directory should not be loaded as a rule."""
        rule = """
id: 409
description: "Test exclusion"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%shells%"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        ph_file = tmp_path / "placeholders.yml"
        ph_file.write_text("shells:\n  - bash\n")

        placeholders = load_placeholders(str(ph_file))
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=str(ph_file))

        assert len(rules) == 1
        assert rules[0].id == 409

    def test_expand_produces_valid_json(self, tmp_path):
        rule = """
id: 410
description: "JSON output test"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|contains|expand: "%shells%"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n  - fish\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ctx)
        json_str = to_json_string(postfix_ctx)

        data = json.loads(json_str)
        assert "id_to_string" in data
        assert "id_to_predicate" in data
        assert "rules" in data
        assert len(data["rules"]) == 1

    def test_no_placeholders_no_expand_works(self, tmp_path):
        """Normal rules without |expand should work fine when no placeholders are provided."""
        rule = """
id: 411
description: "No expand needed"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "test"
    condition: sel
"""
        (tmp_path / "rule.yml").write_text(rule)
        rules = load_sigma_rules(str(tmp_path))
        assert len(rules) == 1
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 1

    def test_expand_list_with_mixed_placeholders_and_literals(self, tmp_path):
        rule = """
id: 412
description: "Mixed list expand"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand:
            - "%shells%"
            - "custom_binary"
    condition: sel
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "bash" in string_values
        assert "zsh" in string_values
        assert "custom_binary" in string_values

    def test_expand_with_not_condition(self, tmp_path):
        rule = """
id: 413
description: "Expand in filter with NOT"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        target.file.path|startswith: "/etc/"
    filter:
        process.file.filename|expand: "%shells%"
    condition: sel and not filter
"""
        ph_file = self._write_rule_and_placeholders(
            tmp_path, rule, "shells:\n  - bash\n  - zsh\n")
        placeholders = load_placeholders(ph_file)
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=ph_file)

        ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ctx)
        data = serialize_context(postfix_ctx)

        assert len(data["rules"]) == 1
        string_values = {entry["value"] for entry in data["id_to_string"].values()}
        assert "bash" in string_values
        assert "zsh" in string_values
        assert "/etc/" in string_values

    def test_expand_does_not_affect_other_rules(self, tmp_path):
        """Ensure that expansion only affects the rule that uses |expand."""
        rule1 = """
id: 414
description: "Rule with expand"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename|expand: "%shells%"
    condition: sel
"""
        rule2 = """
id: 415
description: "Rule without expand"
action: "ALLOW_EVENT"
events: [CHMOD]
detection:
    sel:
        process.file.filename: "normal"
    condition: sel
"""
        (tmp_path / "rule1.yml").write_text(rule1)
        (tmp_path / "rule2.yml").write_text(rule2)
        ph_file = tmp_path / "ph.yml"
        ph_file.write_text("shells:\n  - bash\n")

        placeholders = load_placeholders(str(ph_file))
        rules = load_sigma_rules(str(tmp_path), placeholders=placeholders, placeholder_file=str(ph_file))

        assert len(rules) == 2
        ctx = parse_rules(rules)
        assert len(ctx.rules) == 2

        string_values = {entry.value for entry in ctx.id_to_string.values()}
        assert "bash" in string_values
        assert "normal" in string_values
