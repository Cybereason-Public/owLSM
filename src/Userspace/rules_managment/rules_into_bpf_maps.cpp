#include "rules_into_bpf_maps.hpp"
#include "rule_converter.hpp"
#include "dfa_builder.hpp"
#include "globals/global_strings.hpp"
#include <filesystem>

namespace owlsm 
{
void RulesIntoBpfMaps::create_rule_maps_from_organized_rules(
    const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules,
    const std::unordered_map<int, config::RuleString>& id_to_string,
    const std::unordered_map<int, config::Predicate>& id_to_predicate,
    const std::unordered_map<int, config::RuleIP>& id_to_ip)
{
    populate_predicates_map(id_to_predicate);
    populate_rules_strings_map(id_to_string);
    populate_idx_to_DFA_map(id_to_string);
    populate_idx_to_accepting_states_map();
    populate_rules_ips_map(id_to_ip);
    populate_event_rule_maps(organized_rules);
}

void RulesIntoBpfMaps::populate_predicates_map(const std::unordered_map<int, config::Predicate>& id_to_predicate)
{
    int fd = create_pin_map(BPF_MAP_TYPE_HASH, std::string("predicates_map"), sizeof(struct predicate_t), MAX_TOTAL_PREDS, BPF_F_NO_PREALLOC);
    for (const auto& [id, predicate] : id_to_predicate)
    {
        unsigned int key = static_cast<unsigned int>(id);
        predicate_t c_predicate = RuleStructConverter::convertPredicate(predicate);
        
        if (bpf_map_update_elem(fd, &key, &c_predicate, BPF_ANY) < 0)
        {
            close(fd);
            throw std::system_error(errno, std::generic_category(), "Failed to update predicates_map for predicate id " + std::to_string(id));
        }
    }
    
    freeze_map(fd);
    close(fd);
}

void RulesIntoBpfMaps::populate_rules_strings_map(const std::unordered_map<int, config::RuleString>& id_to_string)
{
    int fd = create_pin_map(BPF_MAP_TYPE_HASH, std::string("rules_strings_map"), sizeof(struct rule_string_t), MAX_TOTAL_PREDS, BPF_F_NO_PREALLOC);
    for (const auto& [id, rule_string] : id_to_string)
    {
        unsigned int key = static_cast<unsigned int>(id);
        rule_string_t c_string = RuleStructConverter::convertRuleString(rule_string);
        
        c_string.idx_to_DFA = (rule_string.string_type != STRING_TYPE_DEFAULT) ? id : -1;
        if (bpf_map_update_elem(fd, &key, &c_string, BPF_ANY) < 0)
        {
            close(fd);
            throw std::system_error(errno, std::generic_category(), "Failed to update rules_strings_map for string id " + std::to_string(id));
        }
    }
    
    freeze_map(fd);
    close(fd);
}

void RulesIntoBpfMaps::populate_idx_to_DFA_map(const std::unordered_map<int, config::RuleString>& id_to_string)
{
    int fd = create_pin_map(BPF_MAP_TYPE_HASH, std::string("idx_to_DFA_map"), sizeof(struct flat_2d_dfa_array_t), MAX_TOTAL_PREDS, BPF_F_NO_PREALLOC);
    for (const auto& [id, rule_string] : id_to_string)
    {
        if (rule_string.string_type == STRING_TYPE_DEFAULT)
        {
            continue;
        }
        
        unsigned int key = static_cast<unsigned int>(id);
        flat_2d_dfa_array_t dfa;
        
        if (rule_string.string_type == STRING_TYPE_CONTAINS)
        {
            DfaBuilder::buildKmpDfa(rule_string.value, dfa);
        }
        else if (rule_string.string_type == STRING_TYPE_REGEX)
        {
            auto result = DfaBuilder::buildRegexDfa(rule_string.value);
            dfa = result.dfa;
            m_regex_accepting_states[id] = result.accepting_states;
        }
        
        if (bpf_map_update_elem(fd, &key, &dfa, BPF_ANY) < 0)
        {
            close(fd);
            throw std::system_error(errno, std::generic_category(), "Failed to update idx_to_DFA_map for string id " + std::to_string(id));
        }
    }
    
    freeze_map(fd);
    close(fd);
}

void RulesIntoBpfMaps::populate_idx_to_accepting_states_map()
{
    if (m_regex_accepting_states.empty())
    {
        return;
    }
    
    int fd = create_pin_map(BPF_MAP_TYPE_HASH, std::string("idx_to_accepting_states_map"), sizeof(unsigned long long), MAX_TOTAL_PREDS, BPF_F_NO_PREALLOC);
    for (const auto& [id, accepting_states] : m_regex_accepting_states)
    {
        unsigned int key = static_cast<unsigned int>(id);
        
        if (bpf_map_update_elem(fd, &key, &accepting_states, BPF_ANY) < 0)
        {
            close(fd);
            throw std::system_error(errno, std::generic_category(), "Failed to update idx_to_accepting_states_map for string id " + std::to_string(id));
        }
    }
    
    freeze_map(fd);
    close(fd);
}

void RulesIntoBpfMaps::populate_rules_ips_map(const std::unordered_map<int, config::RuleIP>& id_to_ip)
{
    if (id_to_ip.empty())
    {
        return;
    }
    
    int fd = create_pin_map(BPF_MAP_TYPE_HASH, std::string("rules_ips_map"), sizeof(struct rule_ip_t), MAX_TOTAL_PREDS, BPF_F_NO_PREALLOC);
    for (const auto& [id, rule_ip] : id_to_ip)
    {
        unsigned int key = static_cast<unsigned int>(id);
        rule_ip_t c_rule_ip = RuleStructConverter::convertRuleIP(rule_ip);
        
        if (bpf_map_update_elem(fd, &key, &c_rule_ip, BPF_ANY) < 0)
        {
            close(fd);
            throw std::system_error(errno, std::generic_category(), "Failed to update rules_ips_map for ip id " + std::to_string(id));
        }
    }
    
    freeze_map(fd);
    close(fd);
}

void RulesIntoBpfMaps::populate_event_rule_maps(
    const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules)
{
    for (const auto& [etype, rules] : organized_rules)
    {
        if (rules.empty())
        {
            continue;
        }
        
        std::string map_name = event_type_to_string(etype);
        int fd = create_pin_map(BPF_MAP_TYPE_ARRAY, map_name, sizeof(rule_t), MAX_RULES_PER_MAP_PLUS1, 0);
        
        for (unsigned int i = 0; i < rules.size(); i++)
        {
            rule_t c_rule = RuleStructConverter::convertRule(*rules[i]);
            if (bpf_map_update_elem(fd, &i, &c_rule, BPF_ANY) < 0)
            {
                close(fd);
                throw std::system_error(errno, std::generic_category(), "Failed to update " + map_name + " for rule index " + std::to_string(i));
            }
        }
        
        freeze_map(fd);
        close(fd);
    }
}

int RulesIntoBpfMaps::create_pin_map(enum bpf_map_type type,const std::string& map_name, size_t value_size, size_t max_entries, int flags)
{
    const std::string pin_path = std::string(owlsm::globals::SYS_FS_BPF_OWLSM_PATH) + "/" + map_name;
    int fd = bpf_obj_get(pin_path.c_str());
    if (fd >= 0)
    {
        return fd;
    }

    std::filesystem::create_directories(owlsm::globals::SYS_FS_BPF_OWLSM_PATH);

    bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;

    fd = bpf_map_create(type, map_name.c_str(), sizeof(unsigned int), value_size, max_entries, &opts);
    if (fd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "bpf_map_create failed for: " + map_name);
    }

    if (bpf_obj_pin(fd, pin_path.c_str()) < 0)
    {
        int err = errno;
        close(fd);
        throw std::system_error(err, std::generic_category(), "bpf_obj_pin failed: " + pin_path);
    }

    return fd;
}

void RulesIntoBpfMaps::freeze_map(int fd)
{
    if (bpf_map_freeze(fd) < 0)
    {
        throw std::system_error(errno, std::generic_category(), "bpf_map_freeze failed");
    }
}

}


