#pragma once
#include "constants.h"
#include "events_structs.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <semver/semver_wrapper.hpp>

namespace owlsm::config {

struct RuleString
{
    std::string value;
    bool is_contains;
};

struct RuleIP
{
    std::string ip;
    int cidr;
    int ip_type;
};

struct Predicate
{
    enum rule_field_type field;
    enum comparison_type comparison_type;
    int string_idx;
    int numerical_value;
    enum rule_field_type fieldref;
};

struct Token
{
    enum operator_types operator_type;
    int predicate_idx;
};

struct RuleMetadata
{
    std::string description;

    bool operator==(const RuleMetadata& other) const
    {
        return description == other.description;
    }
};

struct Rule
{
    unsigned int id;
    enum rule_action action;
    std::vector<enum event_type> applied_events; // TODO: change this to unordered_set
    std::vector<Token> tokens;
    semver::version<int, int, int> min_version;
    semver::version<int, int, int> max_version;
    RuleMetadata metadata;
    bool is_end_of_rules = false;
};

struct RulesConfig
{
    std::unordered_map<int, RuleString> id_to_string;
    std::unordered_map<int, Predicate> id_to_predicate;
    std::unordered_map<int, RuleIP> id_to_ip;
    std::vector<Rule> rules;

    void clear()
    {
        id_to_string.clear();
        id_to_predicate.clear();
        id_to_ip.clear();
        rules.clear();
    }
};

}