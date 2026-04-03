#include "test_base.hpp"
#include "map_populator.hpp"
#include "event_and_rule_matcher_data.hpp"
#include "globals/global_strings.hpp"
#include "system_setup.hpp"
#include "rules_managment/rule_converter.hpp"
#include <string>
#include <cstring>
#include <memory>

struct event_and_rule_matcher_test
{
    struct event_t event;
    struct rule_t rule;
    int actual_result;
};

// Execute BPF test program
template<typename T>
bool execute_matcher_test(T* skel, const event_t& event, const owlsm::config::Rule& rule)
{
    int program_fd = bpf_program__fd(skel->progs.test_event_and_rule_matcher_test_program);
    int map_fd = bpf_map__fd(skel->maps.event_and_rule_matcher_test_map);
    
    event_and_rule_matcher_test test = {};
    test.event = event;
    test.rule = owlsm::RuleStructConverter::convertRule(rule);
    test.actual_result = -1;
    
    unsigned int test_key = 0;
    if (bpf_map_update_elem(map_fd, &test_key, &test, BPF_ANY) < 0)
    {
        throw std::runtime_error("Failed to update test map");
    }
    
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }
    
    if (bpf_map_lookup_elem(map_fd, &test_key, &test) < 0)
    {
        throw std::runtime_error("Failed to lookup test result");
    }
    
    return test.actual_result == 1 ? true : false;
}

std::shared_ptr<owlsm::config::Rule> get_rule_by_id(const std::vector<std::shared_ptr<owlsm::config::Rule>>& rules, unsigned int id)
{
    auto it = std::find_if(rules.begin(), rules.end(), [id](const std::shared_ptr<owlsm::config::Rule>& rule) { return rule->id == id; });
    if (it == rules.end())
    {
        throw std::runtime_error("Rule not found. id: " + std::to_string(id));
    }
    return *it;
}

TEST_F(BpfTestBase, CHMOD_AndOperators_Match)
{
    auto event = test_data::create_chmod_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHMOD_AndOperators_NoMatch)
{
    auto event = test_data::create_chmod_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_AndOperators_Match)
{
    auto event = test_data::create_chown_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_AndOperators_NoMatch)
{
    auto event = test_data::create_chown_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_AndOperators_Match)
{
    auto event = test_data::create_exec_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_AndOperators_NoMatch)
{
    auto event = test_data::create_exec_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EventRuleMatcher_RENAME_AndOperators_Match)
{
    auto event = test_data::create_rename_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EventRuleMatcher_RENAME_AndOperators_NoMatch)
{
    auto event = test_data::create_rename_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EventRuleMatcher_WRITE_AndOperators_Match)
{
    auto event = test_data::create_write_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EventRuleMatcher_WRITE_AndOperators_NoMatch)
{
    auto event = test_data::create_write_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::AND_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 1005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHMOD_OrOperators_Match)
{
    auto event = test_data::create_chmod_or_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHMOD_OrOperators_NoMatch)
{
    auto event = test_data::create_chmod_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_OrOperators_Match)
{
    auto event = test_data::create_chown_or_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_OrOperators_NoMatch)
{
    auto event = test_data::create_chown_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_OrOperators_Match)
{
    auto event = test_data::create_exec_or_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_OrOperators_NoMatch)
{
    auto event = test_data::create_exec_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_OrOperators_Match)
{
    auto event = test_data::create_rename_or_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_OrOperators_NoMatch)
{
    auto event = test_data::create_rename_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, WRITE_OrOperators_Match)
{
    auto event = test_data::create_write_or_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, WRITE_OrOperators_NoMatch)
{
    auto event = test_data::create_write_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHMOD_NotOperators_Match)
{
    auto event = test_data::create_chmod_not_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHMOD_NotOperators_NoMatch)
{
    auto event = test_data::create_chmod_not_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_NotOperators_Match)
{
    auto event = test_data::create_chown_not_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, CHOWN_NotOperators_NoMatch)
{
    auto event = test_data::create_chown_not_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_NotOperators_Match)
{
    auto event = test_data::create_exec_not_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_NotOperators_NoMatch)
{
    auto event = test_data::create_exec_not_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_NotOperators_Match)
{
    auto event = test_data::create_rename_not_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_NotOperators_NoMatch)
{
    auto event = test_data::create_rename_not_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, WRITE_NotOperators_Match)
{
    auto event = test_data::create_write_not_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, WRITE_NotOperators_NoMatch)
{
    auto event = test_data::create_write_not_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::NOT_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 3005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// ============================================================================
// COMPLEX OPERATORS TESTS (AND, OR, NOT combined)
// ============================================================================

TEST_F(BpfTestBase, EXEC_ComplexOperators_MatchViaFirstGroup)
{
    auto event = test_data::create_exec_complex_matching_via_first_group();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_ComplexOperators_MatchViaSecondGroup)
{
    auto event = test_data::create_exec_complex_matching_via_second_group();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_ComplexOperators_NoMatch_Excl1True)
{
    auto event = test_data::create_exec_complex_non_matching_excl1_true();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_ComplexOperators_NoMatch_Excl2True)
{
    auto event = test_data::create_exec_complex_non_matching_excl2_true();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_ComplexOperators_NoMatch_NoGroups)
{
    auto event = test_data::create_exec_complex_non_matching_no_groups();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_ComplexOperators_MatchViaFirstGroup)
{
    auto event = test_data::create_rename_complex_matching_via_first_group();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_ComplexOperators_MatchViaSecondGroup)
{
    auto event = test_data::create_rename_complex_matching_via_second_group();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_ComplexOperators_NoMatch_Excl1True)
{
    auto event = test_data::create_rename_complex_non_matching_excl1_true();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_ComplexOperators_NoMatch_Excl2True)
{
    auto event = test_data::create_rename_complex_non_matching_excl2_true();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_ComplexOperators_NoMatch_NoGroups)
{
    auto event = test_data::create_rename_complex_non_matching_no_groups();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::COMPLEX_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 4002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// Test that without cache, event does NOT match (baseline)
TEST_F(BpfTestBase, PredicatesCache_WithoutCache_NoMatch)
{
    auto event = test_data::create_chmod_cache_test_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, PredicatesCache_WithCache_Match)
{
    auto event = test_data::create_chmod_cache_test_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    
    // Populate cache: pred 2 is TRUE (even though event.process.ruid != 1000)
    // This should make the OR match because at least one predicate is TRUE
    std::vector<MapPopulatorTest::CacheEntry> cache_entries = {
        {0, TOKEN_RESULT_FALSE},
        {1, TOKEN_RESULT_FALSE},
        {2, TOKEN_RESULT_TRUE},
        {3, TOKEN_RESULT_FALSE}
    };
    MapPopulatorTest::populate_predicates_cache(skel, test_data::CACHE_TEST_EVENT_TIME, cache_entries);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, PredicatesCache_CacheFalseOverridesTrue)
{
    auto event = test_data::create_chmod_cache_test_event();
    event.process.ruid = 1000;  // This would make pred 2 evaluate to TRUE
    
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    
    // Populate cache: ALL predicates cached as FALSE
    // Even though pred 2 would evaluate to TRUE, cache overrides it
    std::vector<MapPopulatorTest::CacheEntry> cache_entries = {
        {0, TOKEN_RESULT_FALSE},
        {1, TOKEN_RESULT_FALSE},
        {2, TOKEN_RESULT_FALSE},
        {3, TOKEN_RESULT_FALSE}
    };
    MapPopulatorTest::populate_predicates_cache(skel, test_data::CACHE_TEST_EVENT_TIME, cache_entries);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, PredicatesCache_WrongTimeIgnored)
{
    auto event = test_data::create_chmod_cache_test_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::OR_OPERATORS_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 2001);
    
    std::vector<MapPopulatorTest::CacheEntry> cache_entries = {
        {0, TOKEN_RESULT_FALSE},
        {1, TOKEN_RESULT_FALSE},
        {2, TOKEN_RESULT_TRUE},
        {3, TOKEN_RESULT_FALSE}
    };

    // Use wrong time (event.time is 123456789, we use 999999)
    MapPopulatorTest::populate_predicates_cache(skel, 999999, cache_entries);
    // Cache is ignored because time doesn't match, so actual evaluation happens
    // All predicates evaluate to FALSE, OR doesn't match
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_AllFields_Match)
{
    auto event = test_data::create_rename_all_fields_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::ALL_FIELDS_RENAME_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 5001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, RENAME_AllFields_NoMatch)
{
    auto event = test_data::create_rename_all_fields_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::ALL_FIELDS_RENAME_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 5001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_AllFields_Match)
{
    auto event = test_data::create_exec_all_fields_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::ALL_FIELDS_EXEC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 5002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, EXEC_AllFields_NoMatch)
{
    auto event = test_data::create_exec_all_fields_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::ALL_FIELDS_EXEC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 5002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv4_Mask32_Match)
{
    auto event = test_data::create_network_source_ipv4_mask32_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV4_MASK32_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv4_Mask32_NoMatch)
{
    auto event = test_data::create_network_source_ipv4_mask32_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV4_MASK32_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv4_Mask24_Match)
{
    auto event = test_data::create_network_source_ipv4_mask24_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV4_MASK24_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv4_Mask24_NoMatch)
{
    auto event = test_data::create_network_source_ipv4_mask24_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV4_MASK24_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv4_Mask0_Match)
{
    auto event = test_data::create_network_source_ipv4_mask0_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV4_MASK0_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv6_Mask128_Match)
{
    auto event = test_data::create_network_source_ipv6_mask128_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV6_MASK128_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv6_Mask128_NoMatch)
{
    auto event = test_data::create_network_source_ipv6_mask128_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV6_MASK128_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv6_Mask64_Match)
{
    auto event = test_data::create_network_source_ipv6_mask64_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV6_MASK64_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv6_Mask64_NoMatch)
{
    auto event = test_data::create_network_source_ipv6_mask64_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV6_MASK64_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_SourceIP_IPv6_Mask0_Match)
{
    auto event = test_data::create_network_source_ipv6_mask0_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_SOURCE_IPV6_MASK0_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6006);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv4_Mask32_Match)
{
    auto event = test_data::create_network_dest_ipv4_mask32_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV4_MASK32_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6101);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv4_Mask32_NoMatch)
{
    auto event = test_data::create_network_dest_ipv4_mask32_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV4_MASK32_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6101);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv4_Mask24_Match)
{
    auto event = test_data::create_network_dest_ipv4_mask24_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV4_MASK24_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6102);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv4_Mask24_NoMatch)
{
    auto event = test_data::create_network_dest_ipv4_mask24_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV4_MASK24_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6102);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv4_Mask0_Match)
{
    auto event = test_data::create_network_dest_ipv4_mask0_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV4_MASK0_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6103);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv6_Mask128_Match)
{
    auto event = test_data::create_network_dest_ipv6_mask128_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV6_MASK128_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6104);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv6_Mask128_NoMatch)
{
    auto event = test_data::create_network_dest_ipv6_mask128_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV6_MASK128_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6104);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv6_Mask64_Match)
{
    auto event = test_data::create_network_dest_ipv6_mask64_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV6_MASK64_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6105);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv6_Mask64_NoMatch)
{
    auto event = test_data::create_network_dest_ipv6_mask64_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV6_MASK64_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6105);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, NETWORK_DestIP_IPv6_Mask0_Match)
{
    auto event = test_data::create_network_dest_ipv6_mask0_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::IP_DEST_IPV6_MASK0_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6106);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

// ============================================================================
// FIELDREF NUMERIC TESTS
// ============================================================================

TEST_F(BpfTestBase, Fieldref_Equal_Match)
{
    auto event = test_data::create_fieldref_equal_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Equal_NoMatch)
{
    auto event = test_data::create_fieldref_equal_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gte_Match_Greater)
{
    auto event = test_data::create_fieldref_gte_match_greater();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gte_Match_Equal)
{
    auto event = test_data::create_fieldref_gte_match_equal();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gte_NoMatch)
{
    auto event = test_data::create_fieldref_gte_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gt_Match)
{
    auto event = test_data::create_fieldref_gt_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gt_NoMatch_Equal)
{
    auto event = test_data::create_fieldref_gt_no_match_equal();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Gt_NoMatch_Less)
{
    auto event = test_data::create_fieldref_gt_no_match_less();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lte_Match_Less)
{
    auto event = test_data::create_fieldref_lte_match_less();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lte_Match_Equal)
{
    auto event = test_data::create_fieldref_lte_match_equal();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lte_NoMatch)
{
    auto event = test_data::create_fieldref_lte_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lt_Match)
{
    auto event = test_data::create_fieldref_lt_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lt_NoMatch_Equal)
{
    auto event = test_data::create_fieldref_lt_no_match_equal();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Lt_NoMatch_Greater)
{
    auto event = test_data::create_fieldref_lt_no_match_greater();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Neq_Match)
{
    auto event = test_data::create_fieldref_neq_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7006);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_Neq_NoMatch)
{
    auto event = test_data::create_fieldref_neq_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7006);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_MultipleFieldrefs_Match)
{
    auto event = test_data::create_fieldref_multi_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7007);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Fieldref_MultipleFieldrefs_NoMatch_OneFails)
{
    auto event = test_data::create_fieldref_multi_no_match_one_fails();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_NUMERIC_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 7007);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// ============================================================================
// FIELDREF STRING TESTS
// ============================================================================

// --- Rule 8001: process.file.filename exactmatch process.cmd ---

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Exactmatch_Match)
{
    auto event = test_data::create_fieldref_str_filename_cmd_exactmatch_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_filename_cmd_exactmatch_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8002: process.file.filename startswith process.cmd ---

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Startswith_Match)
{
    auto event = test_data::create_fieldref_str_filename_cmd_startswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_filename_cmd_startswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8003: process.file.filename endswith process.cmd ---

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Endswith_Match)
{
    auto event = test_data::create_fieldref_str_filename_cmd_endswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_filename_cmd_endswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8004: process.cmd exactmatch process.file.filename ---

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Exactmatch_Match)
{
    auto event = test_data::create_fieldref_str_cmd_filename_exactmatch_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_cmd_filename_exactmatch_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8005: process.cmd startswith process.file.filename ---

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Startswith_Match)
{
    auto event = test_data::create_fieldref_str_cmd_filename_startswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_cmd_filename_startswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8006: process.cmd endswith process.file.filename ---

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Endswith_Match)
{
    auto event = test_data::create_fieldref_str_cmd_filename_endswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8006);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_CmdFilename_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_cmd_filename_endswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8006);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8007: process.file.filename neq process.cmd (NOT exactmatch) ---

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Neq_Match)
{
    auto event = test_data::create_fieldref_str_filename_cmd_neq_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8007);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_FilenameCmd_Neq_NoMatch)
{
    auto event = test_data::create_fieldref_str_filename_cmd_neq_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8007);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8008: multiple fieldrefs (filename==cmd AND parent_filename==parent_cmd) ---

TEST_F(BpfTestBase, FieldrefStr_MultipleFieldrefs_Match)
{
    auto event = test_data::create_fieldref_str_multi_fieldref_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8008);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_MultipleFieldrefs_NoMatch_FirstFails)
{
    auto event = test_data::create_fieldref_str_multi_fieldref_no_match_first_fails();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8008);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_MultipleFieldrefs_NoMatch_SecondFails)
{
    auto event = test_data::create_fieldref_str_multi_fieldref_no_match_second_fails();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8008);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Needle longer than haystack: filename shorter than cmd → always FALSE ---

TEST_F(BpfTestBase, FieldrefStr_NeedleLongerThanHaystack_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_needle_longer_than_haystack();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_NeedleLongerThanHaystack_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_needle_longer_than_haystack();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_NeedleLongerThanHaystack_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_needle_longer_than_haystack();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Empty needle (cmd.length == 0): all comparisons must return FALSE ---

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_FilenameCmd_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_FilenameCmd_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_FilenameCmd_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_ParentCmdCmd_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8009);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_ParentCmdCmd_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8010);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_EmptyNeedle_ParentCmdCmd_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_empty_needle();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8011);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8009: parent_cmd exactmatch cmd - max length (255 chars) ---

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Exactmatch_Match)
{
    auto event = test_data::create_fieldref_str_max_len_exactmatch_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8009);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Exactmatch_NoMatch_FirstCharDiffers)
{
    auto event = test_data::create_fieldref_str_max_len_exactmatch_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8009);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8010: parent_cmd startswith cmd - max length ---

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Startswith_Match)
{
    auto event = test_data::create_fieldref_str_max_len_startswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8010);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Startswith_NoMatch_FirstCharDiffers)
{
    auto event = test_data::create_fieldref_str_max_len_startswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8010);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// --- Rule 8011: parent_cmd endswith cmd - max length ---

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Endswith_Match)
{
    auto event = test_data::create_fieldref_str_max_len_endswith_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8011);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_MaxLen_Endswith_NoMatch_LastCharDiffers)
{
    auto event = test_data::create_fieldref_str_max_len_endswith_no_match();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8011);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// parent_cmd (10 chars) shorter than cmd needle (20 chars) → all FALSE
TEST_F(BpfTestBase, FieldrefStr_ParentCmdNeedleLonger_Exactmatch_NoMatch)
{
    auto event = test_data::create_fieldref_str_parent_cmd_needle_longer();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8009);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_ParentCmdNeedleLonger_Startswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_parent_cmd_needle_longer();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8010);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, FieldrefStr_ParentCmdNeedleLonger_Endswith_NoMatch)
{
    auto event = test_data::create_fieldref_str_parent_cmd_needle_longer();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::FIELDREF_STRING_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 8011);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

// =============================================================================
// Regex full-flow tests (userspace DFA build → BPF maps → kernel evaluation)
// =============================================================================

TEST_F(BpfTestBase, Regex_MultiFeature_Match)
{
    auto event = test_data::create_regex_multi_feature_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_MULTI_FEATURE_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_MultiFeature_NoMatch)
{
    auto event = test_data::create_regex_multi_feature_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_MULTI_FEATURE_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_MixedStringTypes_Match)
{
    auto event = test_data::create_mixed_types_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_MIXED_STRING_TYPES_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_MixedStringTypes_NoMatch)
{
    auto event = test_data::create_mixed_types_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_MIXED_STRING_TYPES_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_SameFieldDifferentTypes_Match)
{
    auto event = test_data::create_same_field_diff_types_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_SAME_FIELD_DIFFERENT_TYPES_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6003);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_SameFieldDifferentTypes_NoMatch)
{
    auto event = test_data::create_same_field_diff_types_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_SAME_FIELD_DIFFERENT_TYPES_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6003);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_StateLimit_Match)
{
    auto event = test_data::create_state_limit_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_STATE_LIMIT_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6004);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_StateLimit_NoMatch)
{
    auto event = test_data::create_state_limit_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_STATE_LIMIT_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6004);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_OrLogic_MatchFirst)
{
    auto event = test_data::create_regex_or_matching_event_first();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_WITH_OR_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_OrLogic_MatchSecond)
{
    auto event = test_data::create_regex_or_matching_event_second();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_WITH_OR_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6005);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, Regex_OrLogic_NoMatch)
{
    auto event = test_data::create_regex_or_non_matching_event();
    auto organized_rules = MapPopulatorTest::populate_maps_from_json(test_data::REGEX_WITH_OR_JSON);
    auto rule = get_rule_by_id(organized_rules[event.type], 6005);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}
