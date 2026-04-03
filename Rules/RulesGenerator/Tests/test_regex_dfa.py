"""
Test suite for regex_dfa module.

Tests cover:
- Empty and invalid patterns
- Unsupported regex features  
- DFA state limits (32 max usable states)
- Supported regex features
- Helper functions
- validate_regex_or_raise function
"""
import pytest
from regex_dfa import (
    validate_regex,
    validate_regex_or_raise,
    RegexValidationResult,
    _check_unsupported_features,
    _make_case_insensitive,
    _expand_shorthand_classes,
    _preprocess_pattern_for_greenery,
    SUPPORTED_FEATURES_HELP,
)
from constants import MAX_REGEX_DFA_STATES


class TestEmptyPattern:
    """Tests for empty pattern handling."""
    
    def test_empty_string_rejected(self):
        result = validate_regex("")
        assert result.is_valid is False
        assert "Empty regex pattern" in result.error_message


class TestInvalidSyntax:
    """Tests for invalid regex syntax detection."""
    
    def test_unmatched_paren_open(self):
        result = validate_regex("(abc")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message
    
    def test_unmatched_bracket(self):
        result = validate_regex("[abc")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message
    
    def test_invalid_quantifier_nothing_to_repeat(self):
        result = validate_regex("*abc")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message
    
    def test_invalid_quantifier_range(self):
        result = validate_regex("a{3,1}")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message
    
    def test_invalid_escape_sequence(self):
        result = validate_regex("\\")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message
    
    def test_double_quantifier(self):
        result = validate_regex("a**")
        assert result.is_valid is False
        assert "Invalid regex syntax" in result.error_message


class TestUnsupportedFeatures:
    """Tests for unsupported regex feature detection."""
    
    def test_backreference(self):
        result = validate_regex(r"(a)\1")
        assert result.is_valid is False
        assert "Backreference" in result.error_message
    
    def test_positive_lookahead(self):
        result = validate_regex(r"foo(?=bar)")
        assert result.is_valid is False
        assert "lookahead" in result.error_message.lower()
    
    def test_negative_lookahead(self):
        result = validate_regex(r"foo(?!bar)")
        assert result.is_valid is False
        assert "lookahead" in result.error_message.lower()
    
    def test_positive_lookbehind(self):
        result = validate_regex(r"(?<=foo)bar")
        assert result.is_valid is False
        assert "lookbehind" in result.error_message.lower()
    
    def test_negative_lookbehind(self):
        result = validate_regex(r"(?<!foo)bar")
        assert result.is_valid is False
        assert "lookbehind" in result.error_message.lower()
    
    def test_atomic_group_rejected(self):
        """Atomic groups rejected (by Python's re or our check, depending on version)."""
        result = validate_regex(r"(?>abc)")
        assert result.is_valid is False
    
    def test_named_group(self):
        result = validate_regex(r"(?P<name>abc)")
        assert result.is_valid is False
        assert "Named group" in result.error_message
    
    def test_conditional_pattern_rejected(self):
        """Conditional patterns rejected by Python's re module."""
        result = validate_regex(r"(?(1)yes|no)")
        assert result.is_valid is False
    
    def test_recursive_pattern_rejected(self):
        """Recursive patterns rejected by Python's re module."""
        result = validate_regex(r"a(?R)?b")
        assert result.is_valid is False
    
    def test_possessive_quantifier_rejected(self):
        """Possessive quantifiers rejected (by Python's re or our check, depending on version)."""
        result = validate_regex(r"a*+")
        assert result.is_valid is False


class TestCheckUnsupportedFeaturesHelper:
    """Tests for _check_unsupported_features helper function."""
    
    def test_supported_pattern_returns_none(self):
        assert _check_unsupported_features("abc") is None
        assert _check_unsupported_features("[a-z]+") is None
        assert _check_unsupported_features("(foo|bar)") is None
    
    def test_backreference_returns_error(self):
        error = _check_unsupported_features(r"\1")
        assert error is not None
        assert "Backreference" in error
    
    def test_lookahead_returns_error(self):
        error = _check_unsupported_features(r"(?=test)")
        assert error is not None
        assert "lookahead" in error.lower()


class TestDFAStateLimits:
    """Tests for DFA state count limits."""
    
    def test_max_states_constant_is_32(self):
        assert MAX_REGEX_DFA_STATES == 32
    
    def test_simple_pattern_few_states(self):
        result = validate_regex("a")
        assert result.is_valid is True
        assert result.num_states == 2
        assert result.num_accepting_states == 1
    
    def test_pattern_with_31_repeated_chars_passes(self):
        """'a' * 31 creates 32 unanchored states (skip-loop merges with repeated chars)."""
        result = validate_regex("a" * 31)
        assert result.is_valid is True
        assert result.num_states == 32
    
    def test_pattern_with_32_repeated_chars_fails(self):
        """'a' * 32 creates 33 unanchored states (one over limit)."""
        result = validate_regex("a" * 32)
        assert result.is_valid is False
        assert "too many DFA states" in result.error_message
    
    def test_long_string_exceeds_limit(self):
        result = validate_regex("abcdefghijklmnopqrstuvwxyz12345678")
        assert result.is_valid is False
        assert result.num_states == 35
    
    def test_complex_quantifier_exceeds_limit(self):
        result = validate_regex("(abc|def|ghi){5}")
        assert result.is_valid is False
        assert result.num_states == 36
    
    def test_many_alternations_stays_small(self):
        pattern = "|".join([f"pattern{i}" for i in range(50)])
        result = validate_regex(pattern)
        assert result.is_valid is True
        assert result.num_states <= MAX_REGEX_DFA_STATES


class TestValidPatterns:
    """Tests for valid pattern types."""
    
    def test_literal_string(self):
        result = validate_regex("hello")
        assert result.is_valid is True
    
    def test_character_class_simple(self):
        result = validate_regex("[abc]")
        assert result.is_valid is True
    
    def test_character_class_range(self):
        result = validate_regex("[a-zA-Z0-9]")
        assert result.is_valid is True
    
    def test_character_class_negated(self):
        result = validate_regex("[^abc]")
        assert result.is_valid is True
    
    def test_quantifier_star(self):
        result = validate_regex("a*")
        assert result.is_valid is True
    
    def test_quantifier_plus(self):
        result = validate_regex("a+")
        assert result.is_valid is True
    
    def test_quantifier_question(self):
        result = validate_regex("a?")
        assert result.is_valid is True
    
    def test_quantifier_exact(self):
        result = validate_regex("a{3}")
        assert result.is_valid is True
    
    def test_quantifier_range(self):
        result = validate_regex("a{2,5}")
        assert result.is_valid is True
    
    def test_quantifier_lazy(self):
        result = validate_regex("a*?")
        assert result.is_valid is True
    
    def test_anchor_start(self):
        result = validate_regex("^hello")
        assert result.is_valid is True
    
    def test_anchor_end(self):
        result = validate_regex("hello$")
        assert result.is_valid is True
    
    def test_alternation(self):
        result = validate_regex("cat|dog|bird")
        assert result.is_valid is True
    
    def test_grouping(self):
        result = validate_regex("(abc)+")
        assert result.is_valid is True
    
    def test_non_capturing_group(self):
        result = validate_regex("(?:abc)+")
        assert result.is_valid is True
    
    def test_dot_metacharacter(self):
        result = validate_regex("a.b")
        assert result.is_valid is True
    
    def test_dot_star(self):
        result = validate_regex(".*")
        assert result.is_valid is True
    
    def test_escaped_special_chars(self):
        result = validate_regex(r"\.\*\+\?\|\(\)\[\]\\")
        assert result.is_valid is True


class TestCaseInsensitiveFlag:
    """Tests for case-insensitive flag (?i) support."""
    
    def test_case_insensitive_valid(self):
        result = validate_regex("(?i)hello")
        assert result.is_valid is True
    
    def test_case_insensitive_with_quantifiers(self):
        result = validate_regex("(?i)test+")
        assert result.is_valid is True


class TestMakeCaseInsensitiveHelper:
    """Tests for _make_case_insensitive helper function."""
    
    def test_lowercase_expanded(self):
        result = _make_case_insensitive("abc")
        assert result == "[aA][bB][cC]"
    
    def test_uppercase_expanded(self):
        result = _make_case_insensitive("ABC")
        assert result == "[aA][bB][cC]"
    
    def test_non_alpha_unchanged(self):
        result = _make_case_insensitive("123")
        assert result == "123"
    
    def test_escape_preserved(self):
        result = _make_case_insensitive(r"\d")
        assert result == r"\d"
    
    def test_char_class_content_unchanged(self):
        result = _make_case_insensitive("[abc]")
        assert result == "[abc]"


class TestShorthandClasses:
    """Tests for shorthand character class support."""
    
    def test_digit_class(self):
        result = validate_regex(r"\d+")
        assert result.is_valid is True
    
    def test_word_class(self):
        result = validate_regex(r"\w+")
        assert result.is_valid is True
    
    def test_whitespace_class(self):
        result = validate_regex(r"\s+")
        assert result.is_valid is True
    
    def test_negated_shorthand_classes(self):
        result = validate_regex(r"\D\W\S")
        assert result.is_valid is True


class TestExpandShorthandClassesHelper:
    """Tests for _expand_shorthand_classes helper function."""
    
    def test_digit_expanded(self):
        result = _expand_shorthand_classes(r"\d")
        assert result == "[0-9]"
    
    def test_word_expanded(self):
        result = _expand_shorthand_classes(r"\w")
        assert result == "[a-zA-Z0-9_]"
    
    def test_whitespace_expanded(self):
        result = _expand_shorthand_classes(r"\s")
        assert result == r"[ \t\n\r\f\v]"
    
    def test_non_digit_expanded(self):
        result = _expand_shorthand_classes(r"\D")
        assert result == "[^0-9]"


class TestPreprocessPatternHelper:
    """Tests for _preprocess_pattern_for_greenery helper function."""
    
    def test_case_insensitive_stripped(self):
        result = _preprocess_pattern_for_greenery("(?i)test")
        assert "(?i)" not in result
    
    def test_shorthand_expanded(self):
        result = _preprocess_pattern_for_greenery(r"\d+")
        assert "[0-9]" in result


class TestValidateRegexOrRaise:
    """Tests for validate_regex_or_raise function."""
    
    def test_valid_pattern_no_exception(self):
        validate_regex_or_raise("abc")
    
    def test_empty_pattern_raises(self):
        with pytest.raises(Exception, match="Empty regex pattern"):
            validate_regex_or_raise("")
    
    def test_invalid_syntax_raises(self):
        with pytest.raises(Exception, match="Invalid regex syntax"):
            validate_regex_or_raise("(abc")
    
    def test_unsupported_feature_raises(self):
        with pytest.raises(Exception, match="Backreference"):
            validate_regex_or_raise(r"(a)\1")
    
    def test_context_in_error_message(self):
        with pytest.raises(Exception, match="field_name:.*Empty"):
            validate_regex_or_raise("", context="field_name")


class TestRegexValidationResult:
    """Tests for RegexValidationResult dataclass."""
    
    def test_valid_result_structure(self):
        result = validate_regex("abc")
        assert result.is_valid is True
        assert result.error_message is None
        assert result.num_states == 4
        assert result.num_accepting_states == 1
    
    def test_invalid_result_structure(self):
        result = validate_regex("")
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.num_states == 0
        assert result.num_accepting_states == 0
    
    def test_state_count_on_failure(self):
        """When failing due to state limit, result still has state count."""
        result = validate_regex("a" * 50)
        assert result.is_valid is False
        assert result.num_states == 51


class TestRealWorldPatterns:
    """Tests for real-world regex patterns commonly used in security rules."""
    
    def test_file_extension_pattern(self):
        result = validate_regex(r".*\.exe$")
        assert result.is_valid is True
    
    def test_path_pattern(self):
        result = validate_regex(r"/tmp/.*")
        assert result.is_valid is True
    
    def test_process_pattern(self):
        result = validate_regex(r".*(cmd|bash).*")
        assert result.is_valid is True
    
    def test_ip_address_pattern(self):
        result = validate_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        assert result.is_valid is True
    
    def test_hex_pattern(self):
        result = validate_regex(r"[0-9a-fA-F]+")
        assert result.is_valid is True
    
    def test_url_pattern(self):
        result = validate_regex(r"https?://.*")
        assert result.is_valid is True


class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_single_character(self):
        result = validate_regex("a")
        assert result.is_valid is True
    
    def test_anchor_only(self):
        result = validate_regex("^$")
        assert result.is_valid is True
    
    def test_empty_group(self):
        result = validate_regex("()")
        assert result.is_valid is True
    
    def test_empty_alternation_branch(self):
        result = validate_regex("a|")
        assert result.is_valid is True
    
    def test_unicode_characters(self):
        result = validate_regex("café")
        assert result.is_valid is True
    
    def test_whitespace_literal(self):
        result = validate_regex(" \t\n")
        assert result.is_valid is True


class TestGreeneryLimitations:
    """
    Document patterns that are valid in Python regex but not supported by greenery.
    These tests verify that such patterns are rejected.
    """
    
    def test_hyphen_at_end_of_char_class_rejected(self):
        result = validate_regex("[abc-]")
        assert result.is_valid is False
    
    def test_hyphen_at_start_of_char_class_rejected(self):
        result = validate_regex("[-abc]")
        assert result.is_valid is False
    
    def test_escaped_caret_rejected(self):
        result = validate_regex(r"\^")
        assert result.is_valid is False
    
    def test_escaped_dollar_rejected(self):
        result = validate_regex(r"\$")
        assert result.is_valid is False


class TestSupportedFeaturesHelp:
    """Tests for SUPPORTED_FEATURES_HELP constant."""
    
    def test_help_contains_key_sections(self):
        assert "Literal characters" in SUPPORTED_FEATURES_HELP
        assert "Quantifiers" in SUPPORTED_FEATURES_HELP
        assert "Backreferences" in SUPPORTED_FEATURES_HELP
        assert "Lookahead" in SUPPORTED_FEATURES_HELP
