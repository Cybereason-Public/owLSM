#pragma once

#include "configuration/rule.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <magic_enum/magic_enum.hpp>
#include <semver/semver_wrapper.hpp>
#include <algorithm>
#include <unordered_map>
#include <memory>

namespace owlsm
{
using OrganizedRules = std::unordered_map<event_type, std::vector<std::shared_ptr<config::Rule>>>;
class RulesOrganizer
{
public:
    RulesOrganizer() = default;
    virtual ~RulesOrganizer() = default;
    
    static void add_end_rules(std::vector<config::Rule>& rules)
    {
        config::Rule end_rule = {};
        end_rule.id = __INT_MAX__;
        end_rule.action = ALLOW_EVENT;
        end_rule.applied_events = {EXEC, FILE_CREATE, CHOWN, CHMOD, WRITE, READ, UNLINK, RENAME, NETWORK, MKDIR, RMDIR};
        end_rule.is_end_of_rules = true;
        rules.push_back(end_rule);
    }

    static OrganizedRules organize_rules(std::vector<config::Rule>& rules)
    {
        auto organized = organize_by_event_type(rules);
        filter_out_irrelevant_rules(organized);
        return organized;
    }

private:
    static OrganizedRules organize_by_event_type(std::vector<config::Rule>& rules)
    {
        OrganizedRules organized;
        
        std::vector<std::shared_ptr<config::Rule>> rule_ptrs;
        rule_ptrs.reserve(rules.size());
        for (auto& rule : rules)
        {
            rule_ptrs.push_back(std::make_shared<config::Rule>(rule));
        }
        
        for (const auto& rule_ptr : rule_ptrs)
        {
            for (const auto& event : rule_ptr->applied_events)
            {
                organized[event].push_back(rule_ptr);
            }
        }
        
        for (auto& [event, rules_vec] : organized)
        {
            std::sort(rules_vec.begin(), rules_vec.end(), 
                [](const std::shared_ptr<config::Rule>& a, const std::shared_ptr<config::Rule>& b)
                {
                    return a->id < b->id;
                });
        }
        
        return organized;
    }

    static void filter_out_irrelevant_rules(OrganizedRules& organized)
    {
        filter_out_rules_for_disabled_probes(organized);
        filter_out_rules_by_version(organized);
    }

    static void filter_out_rules_by_version(OrganizedRules& organized)
    {
        semver::version<int, int, int> zero_version;
        semver::version<int, int, int> current_version;
        semver::parse(OWLSM_VERSION_STR, current_version);
        
        for (auto& [event, rules_vec] : organized)
        {
            auto it = std::remove_if(rules_vec.begin(), rules_vec.end(), 
                [&current_version, &zero_version](const std::shared_ptr<config::Rule>& rule)
                {
                    if(rule->min_version != zero_version && current_version < rule->min_version)
                    {
                        LOG_INFO("Removing rule " << rule->id << 
                                " from event " << magic_enum::enum_name(rule->applied_events[0]) << ". Version below minimum supported version.");
                        return true;
                    }
                    if(rule->max_version != zero_version && current_version > rule->max_version)
                    {
                        LOG_INFO("Removing rule " << rule->id <<
                                " from event " << magic_enum::enum_name(rule->applied_events[0]) <<
                                ". Version above maximum supported version.");
                        return true;
                    }
                    return false;
                });
            rules_vec.erase(it, rules_vec.end());
        }
    }

    static void filter_out_rules_for_disabled_probes(OrganizedRules& organized)
    {
        if(!globals::g_config.features.file_monitoring.enabled)
        {
            remove_event_type(organized, CHMOD);
            remove_event_type(organized, CHOWN);
            remove_event_type(organized, FILE_CREATE);
            remove_event_type(organized, MKDIR);
            remove_event_type(organized, RMDIR);
            remove_event_type(organized, UNLINK);
            remove_event_type(organized, RENAME);
            remove_event_type(organized, WRITE);
            remove_event_type(organized, READ);
        }
        else
        {
            if(!globals::g_config.features.file_monitoring.events.chmod) 
            { 
                remove_event_type(organized, CHMOD); 
            }
            if(!globals::g_config.features.file_monitoring.events.chown) 
            { 
                remove_event_type(organized, CHOWN); 
            }
            if(!globals::g_config.features.file_monitoring.events.file_create) 
            { 
                remove_event_type(organized, FILE_CREATE); 
            }
            if(!globals::g_config.features.file_monitoring.events.mkdir) 
            { 
                remove_event_type(organized, MKDIR); 
            }
            if(!globals::g_config.features.file_monitoring.events.rmdir) 
            { 
                remove_event_type(organized, RMDIR); 
            }
            if(!globals::g_config.features.file_monitoring.events.unlink) 
            { 
                remove_event_type(organized, UNLINK); 
            }
            if(!globals::g_config.features.file_monitoring.events.rename) 
            { 
                remove_event_type(organized, RENAME); 
            }
            if(!globals::g_config.features.file_monitoring.events.write) 
            { 
                remove_event_type(organized, WRITE); 
            }
            if(!globals::g_config.features.file_monitoring.events.read) 
            { 
                remove_event_type(organized, READ); 
            }
        }
        
        if(!globals::g_config.features.network_monitoring.enabled)
        {
            remove_event_type(organized, NETWORK);
        }
    }

    static void remove_event_type(OrganizedRules& organized, event_type type)
    {
        auto it = organized.find(type);
        if (it != organized.end())
        {
            LOG_INFO("Removing all rules for event type " << magic_enum::enum_name(type) << ". Probe disabled in config");
            organized.erase(it);
        }
    }
};

}

