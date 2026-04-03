#pragma once
#include "test_base.hpp"
#include "rules_managment/rules_into_bpf_maps.hpp"
#include "rules_managment/dfa_builder.hpp"
#include "rules_managment/rules_organizer.hpp"
#include "configuration/rules_parser.hpp"
#include "rules_structs.h"
#include <nlohmann/json.hpp>
#include <string>
#include <cstring>
#include <stdexcept>

class MapPopulatorTest
{
private:
    static constexpr int TEST_ID = 1;

public:
    static constexpr int get_test_id() { return TEST_ID; }
    
    static void build_dfa(const std::string& pattern, flat_2d_dfa_array_t& dfa)
    {
        owlsm::DfaBuilder::buildKmpDfa(pattern, dfa);
    }
    
    template<typename T>
    static void populate_string_maps(T* skel, const std::string& needle, enum comparison_type test_type)
    {
        int rules_strings_map_fd = bpf_map__fd(skel->maps.rules_strings_map);
        unsigned int key = TEST_ID;
        
        rule_string_t rule_string{};
        strncpy(rule_string.value, needle.c_str(), MAX_RULE_STR_LENGTH - 1);
        rule_string.value[MAX_RULE_STR_LENGTH - 1] = '\0';
        rule_string.length = needle.length();
        
        bool needs_dfa = (test_type == COMPARISON_TYPE_CONTAINS || test_type == COMPARISON_TYPE_REGEX);
        rule_string.idx_to_DFA = needs_dfa ? TEST_ID : -1;
        
        if (bpf_map_update_elem(rules_strings_map_fd, &key, &rule_string, BPF_ANY) < 0)
        {
            throw std::runtime_error("Failed to update rules_strings_map");
        }
        
        if (test_type == COMPARISON_TYPE_CONTAINS && needle.length() > 0)
        {
            int idx_to_DFA_map_fd = bpf_map__fd(skel->maps.idx_to_DFA_map);
            flat_2d_dfa_array_t dfa;
            build_dfa(needle, dfa);
            
            if (bpf_map_update_elem(idx_to_DFA_map_fd, &key, &dfa, BPF_ANY) < 0)
            {
                throw std::runtime_error("Failed to update idx_to_DFA_map");
            }
        }
        else if (test_type == COMPARISON_TYPE_REGEX && needle.length() > 0)
        {
            auto result = owlsm::DfaBuilder::buildRegexDfa(needle);
            
            int idx_to_DFA_map_fd = bpf_map__fd(skel->maps.idx_to_DFA_map);
            if (bpf_map_update_elem(idx_to_DFA_map_fd, &key, &result.dfa, BPF_ANY) < 0)
            {
                throw std::runtime_error("Failed to update idx_to_DFA_map for regex");
            }
            
            int accepting_map_fd = bpf_map__fd(skel->maps.idx_to_accepting_states_map);
            if (bpf_map_update_elem(accepting_map_fd, &key, &result.accepting_states, BPF_ANY) < 0)
            {
                throw std::runtime_error("Failed to update idx_to_accepting_states_map");
            }
        }
    }
    
    template<typename T>
    static void clear_string_maps(T* skel)
    {
        unsigned int key = TEST_ID;
        
        int rules_strings_map_fd = bpf_map__fd(skel->maps.rules_strings_map);
        bpf_map_delete_elem(rules_strings_map_fd, &key);
        
        int idx_to_DFA_map_fd = bpf_map__fd(skel->maps.idx_to_DFA_map);
        bpf_map_delete_elem(idx_to_DFA_map_fd, &key);
        
        int accepting_map_fd = bpf_map__fd(skel->maps.idx_to_accepting_states_map);
        bpf_map_delete_elem(accepting_map_fd, &key);
    }
    
    static owlsm::OrganizedRules populate_maps_from_json(const std::string& json_str)
    {
        nlohmann::json j = nlohmann::json::parse(json_str);
        owlsm::config::RulesParser parser;
        auto config = parser.parse_json_to_rules_config(j);

        auto organized_rules = owlsm::RulesOrganizer::organize_rules(config.rules);
        owlsm::RulesIntoBpfMaps rules_into_bpf_maps;
        rules_into_bpf_maps.create_rule_maps_from_organized_rules(
            organized_rules,
            config.id_to_string,
            config.id_to_predicate,
            config.id_to_ip
        );
        return organized_rules;
    }
    
    struct CacheEntry
    {
        unsigned int predicate_idx;
        enum token_result result;
    };
    
    template<typename T>
    static void populate_predicates_cache(T* skel, unsigned long long event_time, const std::vector<CacheEntry>& entries)
    {
        int cache_fd = bpf_map__fd(skel->maps.predicates_results_cache);
        int nr_cpus = libbpf_num_possible_cpus();
        if (nr_cpus <= 0)
        {
            throw std::runtime_error("Failed to get number of CPUs");
        }
        
        std::vector<predicate_result_t> per_cpu_values(nr_cpus);
        for (const auto& entry : entries)
        {
            for (int i = 0; i < nr_cpus; i++)
            {
                per_cpu_values[i].time = event_time;
                per_cpu_values[i].result = entry.result;
            }
            
            unsigned int key = entry.predicate_idx;
            if (bpf_map_update_elem(cache_fd, &key, per_cpu_values.data(), BPF_ANY) < 0)
            {
                throw std::runtime_error("Failed to update predicates_results_cache for key " + std::to_string(key));
            }
        }
    }
};