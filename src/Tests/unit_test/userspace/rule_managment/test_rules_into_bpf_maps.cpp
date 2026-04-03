#include <gtest/gtest.h>
#include "rules_managment/rules_into_bpf_maps.hpp"
#include "rules_managment/dfa_builder.hpp"
#include <cstring>

class RulesIntoBpfMapsTest : public ::testing::Test 
{
public:
    static void build_dfa(const std::string& pattern, flat_2d_dfa_array_t& dfa)
    {
        owlsm::DfaBuilder::buildKmpDfa(pattern, dfa);
    }

    static std::string event_type_to_string(event_type type)
    {
        owlsm::RulesIntoBpfMaps rules_into_bpf_maps;
        return rules_into_bpf_maps.event_type_to_string(type);
    }
};


TEST_F(RulesIntoBpfMapsTest, build_dfa_single_character)
{
    flat_2d_dfa_array_t dfa;
    std::string pattern = "a";
    RulesIntoBpfMapsTest::build_dfa(pattern, dfa);
    
    // From state 0, seeing 'a' should go to state 1
    size_t idx = (0 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 1);
    
    // From state 0, seeing any other character should stay at 0
    idx = (0 * DFA_ALPHABET_SIZE) + 'b';
    EXPECT_EQ(dfa.value[idx], 0);
    
    // From state 1 (match state), seeing 'a' again should go back to state 1
    idx = (1 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 1);
}

TEST_F(RulesIntoBpfMapsTest, build_dfa_simple_pattern)
{
    flat_2d_dfa_array_t dfa;
    const char* pattern = "abc";
    RulesIntoBpfMapsTest::build_dfa(pattern, dfa);
    
    // State 0 + 'a' -> State 1
    size_t idx = (0 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 1);
    
    // State 1 + 'b' -> State 2
    idx = (1 * DFA_ALPHABET_SIZE) + 'b';
    EXPECT_EQ(dfa.value[idx], 2);
    
    // State 2 + 'c' -> State 3 (match)
    idx = (2 * DFA_ALPHABET_SIZE) + 'c';
    EXPECT_EQ(dfa.value[idx], 3);
    
    // State 0 + 'b' -> State 0 (no match)
    idx = (0 * DFA_ALPHABET_SIZE) + 'b';
    EXPECT_EQ(dfa.value[idx], 0);
}

TEST_F(RulesIntoBpfMapsTest, build_dfa_pattern_with_repetition)
{
    flat_2d_dfa_array_t dfa;
    const char* pattern = "aba";
    RulesIntoBpfMapsTest::build_dfa(pattern, dfa);
    
    // State 0 + 'a' -> State 1
    size_t idx = (0 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 1);
    
    // State 1 + 'b' -> State 2
    idx = (1 * DFA_ALPHABET_SIZE) + 'b';
    EXPECT_EQ(dfa.value[idx], 2);
    
    // State 2 + 'a' -> State 3 (match)
    idx = (2 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 3);
    
    // State 1 + 'a' -> State 1 (failure function, stay at 1 because we have 'a')
    idx = (1 * DFA_ALPHABET_SIZE) + 'a';
    EXPECT_EQ(dfa.value[idx], 1);
}

TEST_F(RulesIntoBpfMapsTest, build_dfa_max_length_pattern)
{
    flat_2d_dfa_array_t dfa;
    std::string pattern(MAX_RULE_STR_LENGTH, 'x');
    
    // Should not crash or throw
    EXPECT_NO_THROW(RulesIntoBpfMapsTest::build_dfa(pattern, dfa));
    
    // Verify first transition
    size_t idx = (0 * DFA_ALPHABET_SIZE) + 'x';
    EXPECT_EQ(dfa.value[idx], 1);
}

TEST_F(RulesIntoBpfMapsTest, event_type_to_string_all_types)
{
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(EXEC), "exec_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(FORK), "fork_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(EXIT), "exit_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(FILE_CREATE), "file_create_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(CHOWN), "chown_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(CHMOD), "chmod_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(WRITE), "write_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(READ), "read_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(UNLINK), "unlink_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(RENAME), "rename_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(NETWORK), "network_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(MKDIR), "mkdir_rules");
    EXPECT_EQ(RulesIntoBpfMapsTest::event_type_to_string(RMDIR), "rmdir_rules");
}