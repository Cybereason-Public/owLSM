#pragma once

#include "configuration/rule.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <semver/semver_wrapper.hpp>
#include <algorithm>

namespace owlsm
{

class FilterOutIrrelevantRules
{
public:
    FilterOutIrrelevantRules() = default;
    virtual ~FilterOutIrrelevantRules() = default;

    static void filter_out_irrelevant_rules(std::vector<config::Rule>& rules)
    {
        filter_out_rules_by_version(rules);
        filter_out_rules_for_disabled_probes(rules);
    }

private:
    static void filter_out_rules_by_version(std::vector<config::Rule>& rules)
    {
        semver::version<int, int, int> zero_version;
        semver::version<int, int, int> current_version;
        semver::parse(OWLSM_VERSION_STR, current_version);
        auto it = std::remove_if(rules.begin(), rules.end(), [&current_version, &zero_version](const config::Rule& rule)
        {
            if(rule.min_version != zero_version && current_version < rule.min_version)
            {
                LOG_INFO("Removing rule " << rule.id << ". Version below minimum supported version.");
                return true;
            }
            if(rule.max_version != zero_version && current_version > rule.max_version)
            {
                LOG_INFO("Removing rule " << rule.id << ". Version above maximum supported version.");
                return true;
            }
            return false;
        });
        rules.erase(it, rules.end());
    }

    static void filter_out_rules_for_disabled_probes(std::vector<config::Rule>& rules)
    {
        if(!globals::g_config.features.file_monitoring.enabled)
        {
            remove_rules_by_type(rules, CHMOD);
            remove_rules_by_type(rules, CHOWN);
            remove_rules_by_type(rules, FILE_CREATE);
            remove_rules_by_type(rules, MKDIR);
            remove_rules_by_type(rules, RMDIR);
            remove_rules_by_type(rules, UNLINK);
            remove_rules_by_type(rules, RENAME);
            remove_rules_by_type(rules, WRITE);
            remove_rules_by_type(rules, READ);
        }
        if(!globals::g_config.features.file_monitoring.events.chmod) { remove_rules_by_type(rules, CHMOD); }
        if(!globals::g_config.features.file_monitoring.events.chown) { remove_rules_by_type(rules, CHOWN); }
        if(!globals::g_config.features.file_monitoring.events.file_create) { remove_rules_by_type(rules, FILE_CREATE); }
        if(!globals::g_config.features.file_monitoring.events.mkdir) { remove_rules_by_type(rules, MKDIR); }
        if(!globals::g_config.features.file_monitoring.events.rmdir) { remove_rules_by_type(rules, RMDIR); }
        if(!globals::g_config.features.file_monitoring.events.unlink) { remove_rules_by_type(rules, UNLINK); }
        if(!globals::g_config.features.file_monitoring.events.rename) { remove_rules_by_type(rules, RENAME); }
        if(!globals::g_config.features.file_monitoring.events.write) { remove_rules_by_type(rules, WRITE); }
        if(!globals::g_config.features.file_monitoring.events.read) { remove_rules_by_type(rules, READ); }
    }

    static void remove_rules_by_type(std::vector<config::Rule>& rules, enum event_type type)
    {
        auto it = std::remove_if(rules.begin(), rules.end(), [&type](const config::Rule& rule)
        {
            if(rule.type == type)
            {
                LOG_INFO("Removing rule " << rule.id << ". Probe disabled in config");
                return true;
            }
            return false;
        });
        rules.erase(it, rules.end());
    }
};

}