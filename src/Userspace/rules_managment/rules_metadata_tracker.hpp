#pragma once

#include "configuration/rule.hpp"
#include "logger.hpp"

#include <unordered_map>
#include <stdexcept>
#include <functional>

namespace std 
{
    template<>
    struct hash<owlsm::config::RuleMetadata>
    {
        std::size_t operator()(const owlsm::config::RuleMetadata& m) const
        {
            std::size_t seed = 0;
            auto hash_combine = [&seed](std::size_t value)
            {
                seed ^= value + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            };

            hash_combine(std::hash<std::string>{}(m.description));
            hash_combine(std::hash<std::string>{}(m.title));
            hash_combine(std::hash<int>{}(static_cast<int>(m.severity)));
            for (const auto& tag : m.mitre_tags)
            {
                hash_combine(std::hash<std::string>{}(tag));
            }
            hash_combine(std::hash<std::string>{}(m.name));
            hash_combine(std::hash<std::string>{}(m.author));
            return seed;
        }
    };
}

namespace owlsm
{

class RulesMetadataTracker
{
public:

    RulesMetadataTracker(const std::vector<config::Rule>& rules)
    {
        for (const auto& rule : rules)
        {
            add_metadata(rule);
        }
    }

    virtual ~RulesMetadataTracker() = default;

    const config::RuleMetadata& get_metadata(unsigned int rule_id) const
    {
        auto rule_it = m_rule_id_to_metadata_id_map.find(rule_id);
        if(rule_it == m_rule_id_to_metadata_id_map.end())
        {
            throw std::runtime_error("Rule ID not found: " + std::to_string(rule_id));
        }

        return *m_id_to_metadata_map.at(rule_it->second);
    }


private:

    void add_metadata(const config::Rule& rule)
    {
        if(m_rule_id_to_metadata_id_map.count(rule.id) > 0)
        {
            return;
        }

        auto it = m_metadata_to_id_map.emplace(rule.metadata, m_metadata_id_counter);
        if(!it.second)
        {
            m_rule_id_to_metadata_id_map[rule.id] = it.first->second;
        }
        else
        {
            m_id_to_metadata_map[m_metadata_id_counter] = &it.first->first;
            m_rule_id_to_metadata_id_map[rule.id] = m_metadata_id_counter;
            m_metadata_id_counter++;
        }
    }

    std::unordered_map<config::RuleMetadata, unsigned int> m_metadata_to_id_map;
    std::unordered_map<unsigned int, const config::RuleMetadata*> m_id_to_metadata_map;
    std::unordered_map<unsigned int, unsigned int> m_rule_id_to_metadata_id_map;
    unsigned int m_metadata_id_counter = 0;
};


}