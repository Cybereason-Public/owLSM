#pragma once
#include "constants.h"
#include "events_structs.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <semver/semver.hpp>

namespace owlsm::config {

struct RuleString
{
    std::string value;
    enum string_type string_type;
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
    std::string title;
    enum rule_severity severity = RULE_SEVERITY_UNKNOWN;
    std::vector<std::string> mitre_tags;
    std::string name;
    std::string author;
    std::string status;

    bool hasAnyValue() const
    {
        return !description.empty() ||
            !title.empty() ||
            severity != RULE_SEVERITY_UNKNOWN ||
            !mitre_tags.empty() ||
            !name.empty() ||
            !author.empty() ||
            !status.empty();
    }

    bool operator==(const RuleMetadata& other) const
    {
        return description == other.description &&
            title == other.title &&
            severity == other.severity &&
            mitre_tags == other.mitre_tags &&
            name == other.name &&
            author == other.author &&
            status == other.status;
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