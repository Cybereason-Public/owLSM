#include "rules_parser.hpp"

#include <semver/semver_wrapper.hpp>

namespace owlsm::config 
{
    RulesConfig RulesParser::parse_json_to_rules_config(const nlohmann::json& json_rules_obj) const
    {
        RulesConfig config;

        if (auto it = json_rules_obj.find("id_to_string"); it != json_rules_obj.end())
        {
            for (auto& [key, value] : it->items())
            {
                int id = std::stoi(key);
                RuleString rule_string;
                from_json(value, rule_string);
                config.id_to_string[id] = rule_string;
            }
        }

        if (auto it = json_rules_obj.find("id_to_predicate"); it != json_rules_obj.end())
        {
            for (auto& [key, value] : it->items())
            {
                int id = std::stoi(key);
                Predicate predicate;
                from_json(value, predicate);
                config.id_to_predicate[id] = predicate;
            }
        }

        if (auto it = json_rules_obj.find("id_to_ip"); it != json_rules_obj.end())
        {
            for (auto& [key, value] : it->items())
            {
                int id = std::stoi(key);
                RuleIP rule_ip;
                from_json(value, rule_ip);
                config.id_to_ip[id] = rule_ip;
            }
        }

        if (auto it = json_rules_obj.find("rules"); it != json_rules_obj.end() && it->is_array())
        {
            config.rules.reserve(it->size());
            for (const auto& json_rule : *it)
            {
                Rule rule;
                from_json(json_rule, rule);
                config.rules.push_back(rule);
            }
        }

        return config;
    }

    void RulesParser::from_json(const nlohmann::json& j, Rule& o) const
    {
        Rule rule;
        o.id = j.at("id").get<unsigned int>();
        
        const auto action_str = j.at("action").get<std::string>();
        o.action = get_enum<rule_action>(action_str);
        
        const auto& events_array = j.at("applied_events");
        o.applied_events.reserve(events_array.size());
        for (const auto& event_str : events_array)
        {
            o.applied_events.push_back(parse_event_type(event_str.get<std::string>()));
        }
        
        const auto& tokens_array = j.at("tokens");
        o.tokens.reserve(tokens_array.size());
        for (const auto& token_json : tokens_array)
        {
            Token token;
            from_json(token_json, token);
            o.tokens.push_back(token);
        }
        
        if (auto it = j.find("min_version"); it != j.end())
        {
            semver::parse(it->get<std::string>(), o.min_version);
        }
        
        if (auto it = j.find("max_version"); it != j.end())
        {
            semver::parse(it->get<std::string>(), o.max_version);
        }
        
        if (auto it = j.find("description"); it != j.end())
        {
            o.metadata.description = it->get<std::string>();
        }
    }

    void RulesParser::from_json(const nlohmann::json& j, Token& o) const
    {
        const auto op_str = j.at("operator_type").get<std::string>();
        o.operator_type = parse_operator_type(op_str);
        
        if (auto it = j.find("predicate_idx"); it != j.end())
        {
            o.predicate_idx = it->get<int>();
        }
        else
        {
            o.predicate_idx = -1;
        }
    }

    void RulesParser::from_json(const nlohmann::json& j, RuleString& o) const
    {
        o.value = j.at("value").get<std::string>();
        o.is_contains = j.at("is_contains").get<bool>();
    }

    void RulesParser::from_json(const nlohmann::json& j, Predicate& o) const
    {
        const auto field_str = j.at("field").get<std::string>();
        o.field = parse_field_id(field_str);
        
        const auto comp_str = j.at("comparison_type").get<std::string>();
        o.comparison_type = parse_comparison_type(comp_str);
        
        o.string_idx = j.at("string_idx").get<int>();
        o.numerical_value = j.at("numerical_value").get<int>();

        const auto fieldref_str = j.at("fieldref").get<std::string>();
        o.fieldref = parse_field_id(fieldref_str);
    }

    void RulesParser::from_json(const nlohmann::json& j, RuleIP& o) const
    {
        o.ip = j.at("ip").get<std::string>();
        o.cidr = j.at("cidr").get<int>();
        o.ip_type = j.at("ip_type").get<int>();
    }

    enum rule_field_type RulesParser::parse_field_id(const std::string& field_str) const
    {
        std::string enum_name = field_str;
        std::transform(enum_name.begin(), enum_name.end(), enum_name.begin(), ::toupper);
        std::replace(enum_name.begin(), enum_name.end(), '.', '_');
        
        auto result = magic_enum::enum_cast<rule_field_type>(enum_name);
        if (result.has_value())
        {
            return result.value();
        }
        throw std::runtime_error("Unknown field: " + field_str + " (tried enum name: " + enum_name + ")");
    }

    enum comparison_type RulesParser::parse_comparison_type(const std::string& comp_str) const
    {
        std::string enum_name = "COMPARISON_TYPE_";
        std::string upper_comp = comp_str;
        std::transform(upper_comp.begin(), upper_comp.end(), upper_comp.begin(), ::toupper);

        if (upper_comp == "STARTSWITH") 
        {
            upper_comp = "STARTS_WITH";
        } 
        else if (upper_comp == "ENDSWITH") 
        {
            upper_comp = "ENDS_WITH";
        }
        else if (upper_comp == "EXACTMATCH")
        {
            upper_comp = "EXACT_MATCH";
        }
        
        enum_name += upper_comp;
        
        const auto result = magic_enum::enum_cast<comparison_type>(enum_name);
        if (result.has_value())
        {
            return result.value();
        }
        throw std::runtime_error("Unknown comparison type: " + comp_str + " (tried enum name: " + enum_name + ")");
    }

    enum operator_types RulesParser::parse_operator_type(const std::string& op_str) const
    {
        const auto result = magic_enum::enum_cast<operator_types>(op_str);
        if (result.has_value())
        {
            return result.value();
        }
        throw std::runtime_error("Unknown operator type: " + op_str);
    }

    enum event_type RulesParser::parse_event_type(const std::string& event_str) const
    {
        const auto result = magic_enum::enum_cast<event_type>(event_str);
        if (result.has_value())
        {
            return result.value();
        }
        throw std::runtime_error("Unknown event type: " + event_str);
    }
}
