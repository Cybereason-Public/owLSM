#include <gtest/gtest.h>
#include "rules_managment/dfa_builder.hpp"
#include "configuration/rules_parser.hpp"

#include <3rd_party/nlohmann/json.hpp>

class DfaBuilderTest : public ::testing::Test
{
public:
    static owlsm::RegexDfaResult buildAndValidate(const std::string& pattern)
    {
        auto result = owlsm::DfaBuilder::buildRegexDfa(pattern);
        validateRegexDfa(result);
        return result;
    }

    static bool matchRegexDfa(const owlsm::RegexDfaResult& result, const std::string& input)
    {
        unsigned char state = 1;
        // Check if start state itself is accepting (patterns matching empty string)
        if ((result.accepting_states >> state) & 1ULL)
        {
            return true;
        }
        for (char ch : input)
        {
            auto c = static_cast<unsigned char>(ch);
            state = result.dfa.value[(state * DFA_ALPHABET_SIZE) + c];
            if ((result.accepting_states >> state) & 1ULL)
            {
                return true;
            }
        }
        return false;
    }

    static void validateRegexDfa(const owlsm::RegexDfaResult& result)
    {
        // State 0 must be the dead state: all transitions loop to itself
        for (int c = 0; c < 256; ++c)
        {
            EXPECT_EQ(result.dfa.value[c], 0) << "Dead state (0) transition on char " << c << " must go to 0";
        }

        // State 0 must not be accepting
        EXPECT_FALSE(result.accepting_states & 1ULL) << "Dead state (0) must not be accepting";

        // Must have at least one accepting state
        EXPECT_NE(result.accepting_states, 0ULL);

        // All transition targets must be within the flat array bounds
        int max_state = findMaxState(result.dfa);
        EXPECT_LT(max_state, DFA_NUM_STATES) << "State ID exceeds flat array capacity";

        // No accepting state beyond the reachable state range
        for (int i = max_state + 1; i < 64; ++i)
        {
            EXPECT_FALSE((result.accepting_states >> i) & 1ULL)
                << "Accepting state " << i << " is beyond the reachable state range (" << max_state << ")";
        }
    }

    static int findMaxState(const flat_2d_dfa_array_t& dfa)
    {
        int max_state = 1;
        for (int state = 0; state <= max_state && state < DFA_NUM_STATES; ++state)
        {
            for (int c = 0; c < 256; ++c)
            {
                int target = dfa.value[(state * DFA_ALPHABET_SIZE) + c];
                if (target > max_state)
                {
                    max_state = target;
                }
            }
        }
        return max_state;
    }
};

// =============================================================================
// Literals
// =============================================================================

TEST_F(DfaBuilderTest, literal_single_char)
{
    auto result = buildAndValidate("x");
    EXPECT_TRUE(matchRegexDfa(result, "x"));
    EXPECT_TRUE(matchRegexDfa(result, "ax"));
    EXPECT_TRUE(matchRegexDfa(result, "xa"));
    EXPECT_TRUE(matchRegexDfa(result, "axa"));
    EXPECT_FALSE(matchRegexDfa(result, "y"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, literal_string)
{
    auto result = buildAndValidate("abc");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "xabc"));
    EXPECT_TRUE(matchRegexDfa(result, "abcx"));
    EXPECT_TRUE(matchRegexDfa(result, "xxabcxx"));
    EXPECT_FALSE(matchRegexDfa(result, "ab"));
    EXPECT_FALSE(matchRegexDfa(result, "abd"));
    EXPECT_FALSE(matchRegexDfa(result, "ABC"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

// =============================================================================
// Character ranges
// =============================================================================

TEST_F(DfaBuilderTest, char_range_lowercase)
{
    auto result = buildAndValidate("[a-z]");
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "m"));
    EXPECT_TRUE(matchRegexDfa(result, "z"));
    EXPECT_TRUE(matchRegexDfa(result, "1a2"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "0"));
    EXPECT_FALSE(matchRegexDfa(result, "123"));
}

TEST_F(DfaBuilderTest, char_range_digits)
{
    auto result = buildAndValidate("[0-9]+");
    EXPECT_TRUE(matchRegexDfa(result, "0"));
    EXPECT_TRUE(matchRegexDfa(result, "42"));
    EXPECT_TRUE(matchRegexDfa(result, "999"));
    EXPECT_TRUE(matchRegexDfa(result, "abc123"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "abc"));
}

TEST_F(DfaBuilderTest, char_range_combined)
{
    auto result = buildAndValidate("[a-zA-Z0-9]");
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "Z"));
    EXPECT_TRUE(matchRegexDfa(result, "5"));
    EXPECT_TRUE(matchRegexDfa(result, "_a_"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "___"));
}

// =============================================================================
// Character classes
// =============================================================================

TEST_F(DfaBuilderTest, char_class_digit)
{
    auto result = buildAndValidate("\\d+");
    EXPECT_TRUE(matchRegexDfa(result, "0"));
    EXPECT_TRUE(matchRegexDfa(result, "123"));
    EXPECT_TRUE(matchRegexDfa(result, "abc123def"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "abc"));
}

TEST_F(DfaBuilderTest, char_class_word)
{
    auto result = buildAndValidate("\\w+");
    EXPECT_TRUE(matchRegexDfa(result, "hello"));
    EXPECT_TRUE(matchRegexDfa(result, "test_123"));
    EXPECT_TRUE(matchRegexDfa(result, " hello "));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, " "));
}

TEST_F(DfaBuilderTest, char_class_space)
{
    auto result = buildAndValidate("\\s+");
    EXPECT_TRUE(matchRegexDfa(result, " "));
    EXPECT_TRUE(matchRegexDfa(result, "\t"));
    EXPECT_TRUE(matchRegexDfa(result, "a b"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "abc"));
}

// =============================================================================
// Negated classes
// =============================================================================

TEST_F(DfaBuilderTest, negated_char_class_digit)
{
    auto result = buildAndValidate("\\D+");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, " "));
    EXPECT_TRUE(matchRegexDfa(result, "a1b"));
    EXPECT_FALSE(matchRegexDfa(result, "5"));
    EXPECT_FALSE(matchRegexDfa(result, "123"));
}

TEST_F(DfaBuilderTest, negated_char_class_word)
{
    auto result = buildAndValidate("\\W");
    EXPECT_TRUE(matchRegexDfa(result, " "));
    EXPECT_TRUE(matchRegexDfa(result, "-"));
    EXPECT_TRUE(matchRegexDfa(result, "a b"));
    EXPECT_FALSE(matchRegexDfa(result, "a"));
    EXPECT_FALSE(matchRegexDfa(result, "abc123"));
}

TEST_F(DfaBuilderTest, negated_char_class_space)
{
    auto result = buildAndValidate("\\S+");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "123"));
    EXPECT_TRUE(matchRegexDfa(result, " a "));
    EXPECT_FALSE(matchRegexDfa(result, " "));
    EXPECT_FALSE(matchRegexDfa(result, "   "));
}

TEST_F(DfaBuilderTest, negated_char_range)
{
    auto result = buildAndValidate("[^/]+");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "file.txt"));
    EXPECT_TRUE(matchRegexDfa(result, "a/b"));
    EXPECT_FALSE(matchRegexDfa(result, "/"));
    EXPECT_FALSE(matchRegexDfa(result, "///"));
}

// =============================================================================
// Dot
// =============================================================================

TEST_F(DfaBuilderTest, dot_matches_printable_ascii)
{
    auto result = buildAndValidate(".");
    EXPECT_TRUE(matchRegexDfa(result, " "));
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "~"));
    EXPECT_TRUE(matchRegexDfa(result, "ab"));
    EXPECT_FALSE(matchRegexDfa(result, ""));

    // Strings with ONLY control chars outside 32-126 should not match
    EXPECT_FALSE(matchRegexDfa(result, std::string(1, '\n')));
    EXPECT_FALSE(matchRegexDfa(result, std::string(1, '\t')));
    EXPECT_FALSE(matchRegexDfa(result, std::string(1, '\x7f')));
}

TEST_F(DfaBuilderTest, dot_in_pattern)
{
    auto result = buildAndValidate("a.c");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "axc"));
    EXPECT_TRUE(matchRegexDfa(result, "a5c"));
    EXPECT_TRUE(matchRegexDfa(result, "a c"));
    EXPECT_TRUE(matchRegexDfa(result, "xxaxcxx"));
    EXPECT_FALSE(matchRegexDfa(result, "ac"));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

// =============================================================================
// Alternation
// =============================================================================

TEST_F(DfaBuilderTest, alternation_simple)
{
    auto result = buildAndValidate("a|b");
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "b"));
    EXPECT_TRUE(matchRegexDfa(result, "xa"));
    EXPECT_FALSE(matchRegexDfa(result, "c"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, alternation_words)
{
    auto result = buildAndValidate("cat|dog");
    EXPECT_TRUE(matchRegexDfa(result, "cat"));
    EXPECT_TRUE(matchRegexDfa(result, "dog"));
    EXPECT_TRUE(matchRegexDfa(result, "hotdog"));
    EXPECT_TRUE(matchRegexDfa(result, "my cat"));
    EXPECT_FALSE(matchRegexDfa(result, "ca"));
    EXPECT_FALSE(matchRegexDfa(result, "dig"));
}

TEST_F(DfaBuilderTest, alternation_three_way)
{
    auto result = buildAndValidate("red|green|blue");
    EXPECT_TRUE(matchRegexDfa(result, "red"));
    EXPECT_TRUE(matchRegexDfa(result, "green"));
    EXPECT_TRUE(matchRegexDfa(result, "blue"));
    EXPECT_TRUE(matchRegexDfa(result, "dark red"));
    EXPECT_FALSE(matchRegexDfa(result, "yellow"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

// =============================================================================
// Repetition
// =============================================================================

TEST_F(DfaBuilderTest, star_matches_zero_or_more)
{
    // a* matches empty string → with unanchored, matches any input
    auto result = buildAndValidate("a*");
    EXPECT_TRUE(matchRegexDfa(result, ""));
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "aaa"));
    EXPECT_TRUE(matchRegexDfa(result, "b"));
    EXPECT_TRUE(matchRegexDfa(result, "xyz"));
}

TEST_F(DfaBuilderTest, plus_matches_one_or_more)
{
    auto result = buildAndValidate("a+");
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "aaaa"));
    EXPECT_TRUE(matchRegexDfa(result, "ba"));
    EXPECT_TRUE(matchRegexDfa(result, "xax"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

TEST_F(DfaBuilderTest, optional_matches_zero_or_one)
{
    // a? matches empty string → with unanchored, matches any input
    auto result = buildAndValidate("a?");
    EXPECT_TRUE(matchRegexDfa(result, ""));
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "b"));
}

TEST_F(DfaBuilderTest, star_with_preceding_literal)
{
    auto result = buildAndValidate("ab*c");
    EXPECT_TRUE(matchRegexDfa(result, "ac"));
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "abbbc"));
    EXPECT_TRUE(matchRegexDfa(result, "xabcx"));
    EXPECT_FALSE(matchRegexDfa(result, "abbb"));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

TEST_F(DfaBuilderTest, star_with_group)
{
    // (ab)* matches empty string → with unanchored, matches any input
    auto result = buildAndValidate("(ab)*");
    EXPECT_TRUE(matchRegexDfa(result, ""));
    EXPECT_TRUE(matchRegexDfa(result, "ab"));
    EXPECT_TRUE(matchRegexDfa(result, "abab"));
    EXPECT_TRUE(matchRegexDfa(result, "xyz"));
}

// =============================================================================
// Bounded repetition
// =============================================================================

TEST_F(DfaBuilderTest, bounded_exact)
{
    auto result = buildAndValidate("a{3}");
    EXPECT_TRUE(matchRegexDfa(result, "aaa"));
    EXPECT_TRUE(matchRegexDfa(result, "xaaax"));
    EXPECT_TRUE(matchRegexDfa(result, "baaab"));
    EXPECT_FALSE(matchRegexDfa(result, "aa"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, bounded_range)
{
    auto result = buildAndValidate("a{2,4}");
    EXPECT_TRUE(matchRegexDfa(result, "aa"));
    EXPECT_TRUE(matchRegexDfa(result, "aaa"));
    EXPECT_TRUE(matchRegexDfa(result, "aaaa"));
    EXPECT_TRUE(matchRegexDfa(result, "xaax"));
    EXPECT_FALSE(matchRegexDfa(result, "a"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, bounded_at_least)
{
    auto result = buildAndValidate("a{2,}");
    EXPECT_TRUE(matchRegexDfa(result, "aa"));
    EXPECT_TRUE(matchRegexDfa(result, "aaa"));
    EXPECT_TRUE(matchRegexDfa(result, "xaaax"));
    EXPECT_FALSE(matchRegexDfa(result, "a"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, bounded_single)
{
    auto result = buildAndValidate("a{1}");
    EXPECT_TRUE(matchRegexDfa(result, "a"));
    EXPECT_TRUE(matchRegexDfa(result, "xa"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

// =============================================================================
// Non-greedy (should produce equivalent DFA to greedy)
// =============================================================================

TEST_F(DfaBuilderTest, non_greedy_star)
{
    auto greedy = buildAndValidate("a*");
    auto non_greedy = buildAndValidate("a*?");

    EXPECT_TRUE(matchRegexDfa(non_greedy, ""));
    EXPECT_TRUE(matchRegexDfa(non_greedy, "a"));
    EXPECT_TRUE(matchRegexDfa(non_greedy, "aaa"));
    EXPECT_TRUE(matchRegexDfa(non_greedy, "b"));

    EXPECT_EQ(greedy.accepting_states, non_greedy.accepting_states);
}

TEST_F(DfaBuilderTest, non_greedy_plus)
{
    auto greedy = buildAndValidate("a+");
    auto non_greedy = buildAndValidate("a+?");

    EXPECT_TRUE(matchRegexDfa(non_greedy, "a"));
    EXPECT_TRUE(matchRegexDfa(non_greedy, "aaa"));
    EXPECT_TRUE(matchRegexDfa(non_greedy, "xa"));
    EXPECT_FALSE(matchRegexDfa(non_greedy, ""));
    EXPECT_FALSE(matchRegexDfa(non_greedy, "xyz"));

    EXPECT_EQ(greedy.accepting_states, non_greedy.accepting_states);
}

// =============================================================================
// Escape sequences
// =============================================================================

TEST_F(DfaBuilderTest, escape_literal_dot)
{
    auto result = buildAndValidate("a\\.b");
    EXPECT_TRUE(matchRegexDfa(result, "a.b"));
    EXPECT_FALSE(matchRegexDfa(result, "axb"));
    EXPECT_FALSE(matchRegexDfa(result, "ab"));
}

TEST_F(DfaBuilderTest, escape_literal_star)
{
    auto result = buildAndValidate("a\\*b");
    EXPECT_TRUE(matchRegexDfa(result, "a*b"));
    EXPECT_FALSE(matchRegexDfa(result, "ab"));
    EXPECT_FALSE(matchRegexDfa(result, "aab"));
}

TEST_F(DfaBuilderTest, escape_backslash)
{
    auto result = buildAndValidate("a\\\\b");
    EXPECT_TRUE(matchRegexDfa(result, "a\\b"));
    EXPECT_FALSE(matchRegexDfa(result, "ab"));
}

TEST_F(DfaBuilderTest, escape_tab)
{
    auto result = buildAndValidate("a\\tb");
    EXPECT_TRUE(matchRegexDfa(result, std::string("a\tb")));
    EXPECT_FALSE(matchRegexDfa(result, "a b"));
    EXPECT_FALSE(matchRegexDfa(result, "atb"));
}

TEST_F(DfaBuilderTest, escape_newline)
{
    auto result = buildAndValidate("a\\nb");
    EXPECT_TRUE(matchRegexDfa(result, std::string("a\nb")));
    EXPECT_FALSE(matchRegexDfa(result, "anb"));
}

// =============================================================================
// Case insensitive
// =============================================================================

TEST_F(DfaBuilderTest, case_insensitive_literal)
{
    auto result = buildAndValidate("(?i)abc");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "ABC"));
    EXPECT_TRUE(matchRegexDfa(result, "AbC"));
    EXPECT_TRUE(matchRegexDfa(result, "aBc"));
    EXPECT_TRUE(matchRegexDfa(result, "xABCx"));
    EXPECT_FALSE(matchRegexDfa(result, "ab"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, case_insensitive_char_range)
{
    auto result = buildAndValidate("(?i)[a-c]+");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "ABC"));
    EXPECT_TRUE(matchRegexDfa(result, "AaBbCc"));
    EXPECT_FALSE(matchRegexDfa(result, "d"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
}

TEST_F(DfaBuilderTest, case_insensitive_does_not_affect_digits)
{
    auto result = buildAndValidate("(?i)a1b");
    EXPECT_TRUE(matchRegexDfa(result, "a1b"));
    EXPECT_TRUE(matchRegexDfa(result, "A1B"));
    EXPECT_FALSE(matchRegexDfa(result, "a2b"));
}

// =============================================================================
// Complex patterns
// =============================================================================

TEST_F(DfaBuilderTest, complex_alternation_with_repetition)
{
    auto result = buildAndValidate("(a|b)+c");
    EXPECT_TRUE(matchRegexDfa(result, "ac"));
    EXPECT_TRUE(matchRegexDfa(result, "bc"));
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "xbcx"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

TEST_F(DfaBuilderTest, complex_digit_dot_digit)
{
    auto result = buildAndValidate("\\d+\\.\\d+");
    EXPECT_TRUE(matchRegexDfa(result, "3.14"));
    EXPECT_TRUE(matchRegexDfa(result, "0.0"));
    EXPECT_TRUE(matchRegexDfa(result, "192.168"));
    EXPECT_FALSE(matchRegexDfa(result, ".5"));
    EXPECT_FALSE(matchRegexDfa(result, "3."));
    EXPECT_FALSE(matchRegexDfa(result, "3"));
}

TEST_F(DfaBuilderTest, complex_path_pattern)
{
    auto result = buildAndValidate("/tmp/[a-z]+");
    EXPECT_TRUE(matchRegexDfa(result, "/tmp/abc"));
    EXPECT_TRUE(matchRegexDfa(result, "/tmp/test"));
    EXPECT_TRUE(matchRegexDfa(result, "xx/tmp/abcxx"));
    EXPECT_FALSE(matchRegexDfa(result, "/tmp/"));
    EXPECT_FALSE(matchRegexDfa(result, "/var/abc"));
}

TEST_F(DfaBuilderTest, complex_optional_prefix)
{
    auto result = buildAndValidate("https?://");
    EXPECT_TRUE(matchRegexDfa(result, "http://"));
    EXPECT_TRUE(matchRegexDfa(result, "https://"));
    EXPECT_TRUE(matchRegexDfa(result, "visit http://x"));
    EXPECT_FALSE(matchRegexDfa(result, "ftp://"));
}

TEST_F(DfaBuilderTest, complex_nested_groups)
{
    auto result = buildAndValidate("((ab)+c)+");
    EXPECT_TRUE(matchRegexDfa(result, "abc"));
    EXPECT_TRUE(matchRegexDfa(result, "ababc"));
    EXPECT_TRUE(matchRegexDfa(result, "xabcx"));
    EXPECT_FALSE(matchRegexDfa(result, ""));
    EXPECT_FALSE(matchRegexDfa(result, "xyz"));
}

// =============================================================================
// Char class escapes inside brackets
// =============================================================================

TEST_F(DfaBuilderTest, digit_class_inside_brackets)
{
    auto result = buildAndValidate("[\\d]+");
    EXPECT_TRUE(matchRegexDfa(result, "123"));
    EXPECT_FALSE(matchRegexDfa(result, "abc"));
}

TEST_F(DfaBuilderTest, mixed_range_and_escape_in_brackets)
{
    auto result = buildAndValidate("[a-z\\d]+");
    EXPECT_TRUE(matchRegexDfa(result, "abc123"));
    EXPECT_TRUE(matchRegexDfa(result, "test"));
    EXPECT_TRUE(matchRegexDfa(result, "42"));
    EXPECT_FALSE(matchRegexDfa(result, "ABC"));
    EXPECT_FALSE(matchRegexDfa(result, " "));
}

// =============================================================================
// State limits
// =============================================================================

TEST_F(DfaBuilderTest, state_limit_at_maximum)
{
    // With unanchored, a 30-char unique literal produces ~31 DFA states + dead = 32.
    std::string pattern(30, 'a');
    for (int i = 0; i < 30; ++i)
    {
        pattern[i] = 'a' + (i % 26);
    }

    owlsm::RegexDfaResult result;
    EXPECT_NO_THROW(result = buildAndValidate(pattern));
    EXPECT_TRUE(matchRegexDfa(result, pattern));
    EXPECT_TRUE(matchRegexDfa(result, "xxx" + pattern + "xxx"));
    EXPECT_FALSE(matchRegexDfa(result, pattern.substr(0, 29)));
}

TEST_F(DfaBuilderTest, state_limit_exceeded_throws)
{
    // A sufficiently long unique-char literal exceeds MAX_REGEX_DFA_STATES with unanchored
    std::string pattern(31, 'a');
    for (int i = 0; i < 31; ++i)
    {
        pattern[i] = 'a' + (i % 26);
    }

    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa(pattern), std::runtime_error);
}

// =============================================================================
// Error handling
// =============================================================================

TEST_F(DfaBuilderTest, empty_pattern_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa(""), std::runtime_error);
}

TEST_F(DfaBuilderTest, unmatched_open_paren_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("(abc"), std::runtime_error);
}

TEST_F(DfaBuilderTest, unmatched_close_paren_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("abc)"), std::runtime_error);
}

TEST_F(DfaBuilderTest, unmatched_bracket_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("[abc"), std::runtime_error);
}

TEST_F(DfaBuilderTest, invalid_repetition_bounds_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("a{5,3}"), std::runtime_error);
}

TEST_F(DfaBuilderTest, repetition_zero_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("a{0}"), std::runtime_error);
}

TEST_F(DfaBuilderTest, invalid_char_range_throws)
{
    EXPECT_THROW(owlsm::DfaBuilder::buildRegexDfa("[z-a]"), std::runtime_error);
}

// =============================================================================
// Minimization correctness
// =============================================================================

TEST_F(DfaBuilderTest, redundant_alternation_minimizes)
{
    auto single = buildAndValidate("a");
    auto redundant = buildAndValidate("a|a");

    int single_states = findMaxState(single.dfa) + 1;
    int redundant_states = findMaxState(redundant.dfa) + 1;
    EXPECT_EQ(single_states, redundant_states);

    EXPECT_TRUE(matchRegexDfa(redundant, "a"));
    EXPECT_FALSE(matchRegexDfa(redundant, "b"));
}

// =============================================================================
// Config parsing: CONTAINS and REGEX coexisting on the same field
// =============================================================================

TEST_F(DfaBuilderTest, config_parse_contains_and_regex_same_field)
{
    const char* json_str = R"({
        "id_to_string": {
            "0": {"value": "a[bc]d", "string_type": 1},
            "1": {"value": "a[bc]d", "string_type": 2}
        },
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1,
                "fieldref": "FIELD_TYPE_NONE"
            },
            "1": {
                "field": "target.file.path",
                "comparison_type": "regex",
                "string_idx": 1,
                "numerical_value": -1,
                "fieldref": "FIELD_TYPE_NONE"
            }
        },
        "id_to_ip": {},
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["READ"],
                "tokens": [
                    {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
                    {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
                    {"operator_type": "OPERATOR_OR"}
                ]
            }
        ]
    })";

    nlohmann::json j = nlohmann::json::parse(json_str);
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);

    // Both strings parsed with same value but different string_type
    ASSERT_EQ(config.id_to_string.size(), 2);
    EXPECT_EQ(config.id_to_string[0].value, "a[bc]d");
    EXPECT_EQ(config.id_to_string[0].string_type, STRING_TYPE_CONTAINS);
    EXPECT_EQ(config.id_to_string[1].value, "a[bc]d");
    EXPECT_EQ(config.id_to_string[1].string_type, STRING_TYPE_REGEX);

    // Predicates parsed with correct comparison types
    ASSERT_EQ(config.id_to_predicate.size(), 2);
    EXPECT_EQ(config.id_to_predicate[0].comparison_type, COMPARISON_TYPE_CONTAINS);
    EXPECT_EQ(config.id_to_predicate[1].comparison_type, COMPARISON_TYPE_REGEX);

    // The CONTAINS string should build a KMP DFA (literal "a[bc]d")
    flat_2d_dfa_array_t kmp_dfa;
    EXPECT_NO_THROW(owlsm::DfaBuilder::buildKmpDfa(config.id_to_string[0].value, kmp_dfa));

    // The REGEX string should build a regex DFA (pattern a[bc]d)
    owlsm::RegexDfaResult regex_result;
    EXPECT_NO_THROW(regex_result = owlsm::DfaBuilder::buildRegexDfa(config.id_to_string[1].value));
    validateRegexDfa(regex_result);

    // Regex "a[bc]d" should match "abd" and "acd" anywhere in the string
    EXPECT_TRUE(matchRegexDfa(regex_result, "abd"));
    EXPECT_TRUE(matchRegexDfa(regex_result, "acd"));
    EXPECT_TRUE(matchRegexDfa(regex_result, "xxabdxx"));
    EXPECT_FALSE(matchRegexDfa(regex_result, "aed"));
    EXPECT_FALSE(matchRegexDfa(regex_result, "xyz"));
}
