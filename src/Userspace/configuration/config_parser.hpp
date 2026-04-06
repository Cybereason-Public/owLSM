#pragma once

#include "configuration/config.hpp"

#include <nlohmann/json.hpp>

class ConfigParserTest;

namespace owlsm::config {

class ConfigParser
{
public:
    ConfigParser(const std::string& json_str, const std::string& schema_str);
    virtual ~ConfigParser() = default;
    ConfigParser(const ConfigParser&) = delete;
    ConfigParser(ConfigParser&&) = delete;
    ConfigParser& operator=(const ConfigParser&) = delete;
    ConfigParser& operator=(ConfigParser&&) = delete;

    const Config& getConfig() const { return m_config; }
    void ClearRules() { m_config.rules_config.clear(); }

private:
    nlohmann::json createJsonObject(const std::string& json_str);
    void validateJsonAgainstSchema(const nlohmann::json& instance, const nlohmann::json& schema_json);
    void parseJsonToConfigObject(const nlohmann::json& j);
    void fromJson(const nlohmann::json& j, FeaturesConfig& o);
    void fromJson(const nlohmann::json& j, FileMonitoringConfig& o);
    void fromJson(const nlohmann::json& j, FileMonitoringEventsConfig& o);
    void fromJson(const nlohmann::json& j, NetworkMonitoringConfig& o);
    void fromJson(const nlohmann::json& j, ShellCommandsMonitoringConfig& o);
    void fromJson(const nlohmann::json& j, UserspaceConfig& o);
    void fromJson(const nlohmann::json& j, KernelConfig& o);
    
    Config m_config;

    friend class ::ConfigParserTest;
};

}