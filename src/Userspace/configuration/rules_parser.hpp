#pragma once

#include <3rd_party/magic_enum/magic_enum.hpp>
#include <3rd_party/nlohmann/json.hpp>

#include "rule.hpp"

namespace owlsm::config {

template <class Enum>
Enum get_enum(const nlohmann::json& j) 
{
    if (j.is_string()) 
    {
        auto v = magic_enum::enum_cast<Enum>(j.get<std::string>());
        if (!v) 
        {
            throw std::runtime_error("bad enum: " + j.get<std::string>());
        }
        return *v;
    }
    return static_cast<Enum>(j.get<int>());
}

template <class T>
void get_if_present(const nlohmann::json& j, const char* key, T& out) 
{
    auto it = j.find(key);
    if (it != j.end() && !it->is_null()) 
    {
        out = it->get<T>();
    }
}

class RulesParser
{
public:
    RulesParser() = default;
    virtual ~RulesParser() = default;
    RulesParser(const RulesParser&) = delete;
    RulesParser(RulesParser&&) = delete;
    RulesParser& operator=(const RulesParser&) = delete;
    RulesParser& operator=(RulesParser&&) = delete;

    RulesConfig parse_json_to_rules_config(const nlohmann::json& json_rules_obj) const;

private:
    enum rule_field_type parse_field_id(const std::string& field_str) const;
    enum comparison_type parse_comparison_type(const std::string& comp_str) const;
    enum operator_types parse_operator_type(const std::string& op_str) const;
    enum event_type parse_event_type(const std::string& event_str) const;
    enum rule_severity parse_rule_severity(const std::string& severity_str) const;
    void from_json(const nlohmann::json& j, RuleString& o) const;
    void from_json(const nlohmann::json& j, Predicate& o) const;
    void from_json(const nlohmann::json& j, RuleIP& o) const;
    void from_json(const nlohmann::json& j, Token& o) const;
    void from_json(const nlohmann::json& j, Rule& o) const;
};

}