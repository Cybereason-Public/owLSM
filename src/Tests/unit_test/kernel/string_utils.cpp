#include "test_base.hpp"
#include "map_populator.hpp"
#include <string>
#include <cstring>

struct StringUtilsTestCase 
{ 
    std::string haystack;
    std::string needle; 
    enum comparison_type test_type;
};

template<typename T>
bool executeBpfProgram(T* skel, const StringUtilsTestCase& test_case)
{
    MapPopulatorTest::clear_string_maps(skel);
    MapPopulatorTest::populate_string_maps(skel, test_case.needle, test_case.test_type);
    
    int program_fd = bpf_program__fd(skel->progs.test_string_utils_program);
    int map_fd  = bpf_map__fd(skel->maps.test_string_utils_map);
    
    string_utils_test t{};
    t.id = MapPopulatorTest::get_test_id();
    strncpy(t.haystack, test_case.haystack.c_str(), PATH_MAX);
    strncpy(t.needle,   test_case.needle.c_str(), MAX_NEEDLE_LENGTH);
    t.haystack_length = test_case.haystack.length();
    t.needle_length = test_case.needle.length();
    t.test_type = test_case.test_type;
    t.actual_result = -1;

    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}

    bpf_map_lookup_elem(map_fd, &key, &t);
    
    MapPopulatorTest::clear_string_maps(skel);
    
    return t.actual_result;
}

TEST_F(BpfTestBase, StringUtils_ExactMatchTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello worl", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "ello worl", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "helloworld", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_EXACT_MATCH}));
}

TEST_F(BpfTestBase, StringUtils_ContainsTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_StartsWithTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_STARTS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_EndsWithTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_SpecialCharactersTest) 
{
    // Test with special characters (file paths)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "/usr/bin/bash", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "/usr", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "bash", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "bin", COMPARISON_TYPE_CONTAINS}));
    
    // Test with special regex-like characters (should be treated literally)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test.*file", ".*", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"file[123]", "[123]", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test$var", "$var", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_RepeatedPatternsTest) 
{
    // Test patterns with repeated characters (stress test for KMP DFA)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaaaaab", "aaab", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abababab", "ababab", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abcabc", COMPARISON_TYPE_CONTAINS}));
    
    // Partial matches that should fail
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abababab", "abababac", COMPARISON_TYPE_CONTAINS}));
    
    // Test with pattern at the very end
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xxxxxxxxxabc", "abc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xxxxxxxxxabc", "abc", COMPARISON_TYPE_ENDS_WITH}));
    
    // Test with pattern at the very beginning
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcxxxxxxxxx", "abc", COMPARISON_TYPE_STARTS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_SingleCharacterTest) 
{
    // Single character searches
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a", "a", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "a", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "c", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "b", COMPARISON_TYPE_CONTAINS}));
    
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "d", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"a", "b", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Single character repeated
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaaa", "a", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"baaa", "a", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_CaseSensitivityTest) 
{
    // Verify case sensitivity (all should be case-sensitive)
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "WORLD", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "HELLO", COMPARISON_TYPE_CONTAINS}));
    
    // Same case should match
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "Hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "World", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "lo Wo", COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_WhitespaceTest) 
{
    // Test with various whitespace
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", " ", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"  leading", "  ", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"trailing  ", "  ", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"\t\n", "\t\n", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Whitespace differences should fail exact match
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello  world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello\tworld", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
}

TEST_F(BpfTestBase, StringUtils_OverlappingPatternTest) 
{
    // Test overlapping patterns where naive search might fail (critical for DFA correctness)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aabaacaabaa", "aabaa", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abacababc", "ababc", COMPARISON_TYPE_CONTAINS}));
    
    // Pattern appears multiple times
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_ENDS_WITH}));
    
    // Complex overlapping pattern
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"ababababc", "ababc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ababababd", "ababc", COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_NumericTest) 
{
    // Numeric strings
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "123", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "345", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "234", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "12345", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Mixed alphanumeric
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test123file", "123", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"v1.2.3", "1.2", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"file_v2.0.1", "v2.0.1", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_BoundaryLengthTest) 
{
    // Test at MAX_NEEDLE_LENGTH boundary (32 bytes)
    std::string max_needle(MAX_NEEDLE_LENGTH, 'x');
    std::string haystack_with_max(PATH_MAX - 1, 'x');
    
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{haystack_with_max, max_needle, COMPARISON_TYPE_CONTAINS}));
    std::string needle_31(MAX_NEEDLE_LENGTH - 1, 'a');
    std::string haystack_31(MAX_NEEDLE_LENGTH - 1, 'a');
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{haystack_31, needle_31, COMPARISON_TYPE_EXACT_MATCH}));
    
    // Test with different character at boundary
    std::string needle_max_b(MAX_NEEDLE_LENGTH, 'b');
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{haystack_with_max, needle_max_b, COMPARISON_TYPE_CONTAINS}));
}

// =============================================================================
// Regex DFA tests (full kernel path: userspace DFA build → BPF regex_dfa_search)
// =============================================================================

TEST_F(BpfTestBase, StringUtils_Regex_LiteralMatch)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "abc", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xabcx", "abc", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "abc", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abd", "abc", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ab", "abc", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_CharRangeAndRepetition)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc123", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"123", "[a-z]+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_CharClasses)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"123", "\\d+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc123", "\\d+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "\\d+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test_123", "\\w+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test 123", "\\w+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_Dot)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "a.c", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a5c", "a.c", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ac", "a.c", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abbc", "a.c", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_Alternation)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"cat", "cat|dog", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"dog", "cat|dog", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hotdog", "cat|dog", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"bird", "cat|dog", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_StarAndOptional)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"ac", "ab*c", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "ab*c", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abbbbc", "ab*c", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"adc", "ab*c", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"http://", "https?://", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"https://", "https?://", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"httpx://", "https?://", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_BoundedRepetition)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaa", "a{3}", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xaaax", "a{3}", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"aa", "a{3}", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aa", "a{2,4}", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xaax", "a{2,4}", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"a", "a{2,4}", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_CaseInsensitive)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello", "(?i)hello", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"HELLO", "(?i)hello", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"HeLLo", "(?i)hello", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hell", "(?i)hello", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_EscapedChars)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a.b", "a\\.b", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"axb", "a\\.b", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a*b", "a\\*b", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ab", "a\\*b", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_ComplexPatterns)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/tmp/app.log", "/tmp/[a-z]+\\.log", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"/tmp/App.log", "/tmp/[a-z]+\\.log", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"/var/app.log", "/tmp/[a-z]+\\.log", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"/tmp/app.txt", "/tmp/[a-z]+\\.log", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"3.14", "\\d+\\.\\d+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"3", "\\d+\\.\\d+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"3.", "\\d+\\.\\d+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_NestedGroups)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"ababc", "((ab)+c)+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcababc", "((ab)+c)+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ab", "((ab)+c)+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_StateLimit)
{
    // 30-char unique literal → 32 DFA states (dead + start + 30 intermediate)
    std::string pattern_30 = "abcdefghijklmnopqrstuvwxyz1234";
    std::string haystack_match = pattern_30;
    std::string haystack_short = pattern_30.substr(0, 29);

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{haystack_match, pattern_30, COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{haystack_short, pattern_30, COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_MaxLengthInput_ComplexPath)
{
    // 255-char haystack: long path matched by a regex with mixed features
    std::string long_path(PATH_MAX - 1 - 8, 'a');
    long_path = "/" + long_path + "/x.conf";
    ASSERT_EQ(long_path.size(), PATH_MAX - 1);

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{long_path, "/[a-z]+/[a-z]+\\.conf", COMPARISON_TYPE_REGEX}));

    std::string no_match_path = long_path;
    no_match_path.back() = 'x';
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{no_match_path, "/[a-z]+/[a-z]+\\.conf", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_MaxLengthInput_MatchAtEnd)
{
    // The meaningful match is at the very end of a 255-char string.
    // Regex checks that the string is lowercase/slash chars ending in ".log"
    std::string long_path(PATH_MAX - 1 - 4, 'z');
    long_path[0] = '/';
    long_path += ".log";
    ASSERT_EQ(long_path.size(), PATH_MAX - 1);

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{long_path, "[a-z/]+\\.log", COMPARISON_TYPE_REGEX}));

    // Same length but ending in ".txt" → no match
    std::string no_match = long_path;
    no_match.replace(no_match.size() - 4, 4, ".txt");
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{no_match, "[a-z/]+\\.log", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_NegatedCharRange)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello", "[^0-9]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc123", "[^0-9]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"42", "[^0-9]+", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "[^/]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a/b", "[^/]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"/", "[^/]+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_NegatedCharClasses)
{
    // \D matches non-digits
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "\\D+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc1", "\\D+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"123", "\\D+", COMPARISON_TYPE_REGEX}));

    // \W matches non-word chars
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{" -.", "\\W+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a b", "\\W+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "\\W+", COMPARISON_TYPE_REGEX}));

    // \S matches non-space chars
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "\\S+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{" a ", "\\S+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{" ", "\\S+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_SpaceClass)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{" ", "\\s+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(1, '\t'), "\\s+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{" \t ", "\\s+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "\\s+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_AtLeastBounded)
{
    // {2,} means 2 or more
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aa", "a{2,}", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaaaa", "a{2,}", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"a", "a{2,}", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "a{2,}", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_PlusRepetition)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcdef", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "[a-z]+", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"123", "[a-z]+", COMPARISON_TYPE_REGEX}));
}

TEST_F(BpfTestBase, StringUtils_Regex_EscapeSequences)
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string("a\tb"), "a\\tb", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"atb", "a\\tb", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string("a\nb"), "a\\nb", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"anb", "a\\nb", COMPARISON_TYPE_REGEX}));

    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a\\b", "a\\\\b", COMPARISON_TYPE_REGEX}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ab", "a\\\\b", COMPARISON_TYPE_REGEX}));
}