#include "config_parser.hpp"
#include "configuration/rules_parser.hpp"

#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>
#include <valijson/adapters/nlohmann_json_adapter.hpp>

namespace owlsm::config {

    ConfigParser::ConfigParser(const std::string& json_str, const std::string& schema_str)
    {
        nlohmann::json j = createJsonObject(json_str);
        nlohmann::json schema = nlohmann::json::parse(schema_str);
        validateJsonAgainstSchema(j, schema);
        parseJsonToConfigObject(j);
    }


    nlohmann::json ConfigParser::createJsonObject(const std::string& json_str)
    {
        return nlohmann::json::parse(json_str);
    }

    void ConfigParser::validateJsonAgainstSchema(const nlohmann::json& instance, const nlohmann::json& schema_json)
    {
        valijson::Schema schema;
        valijson::SchemaParser parser;
        valijson::adapters::NlohmannJsonAdapter schema_adapter(schema_json);
        parser.populateSchema(schema_adapter, schema);  
        valijson::Validator validator;
        valijson::adapters::NlohmannJsonAdapter instance_adapter(instance);
        valijson::ValidationResults results;
        if (validator.validate(schema, instance_adapter, &results))
        {
            return;
        }

        std::string msg = "Schema validation failed:\n";
        valijson::ValidationResults::Error e;
        while (results.popError(e)) 
        {
            msg += " - " + e.description + " @ " + e.jsonPointer + "\n";
        }
        throw std::runtime_error(msg);
    }

    void ConfigParser::parseJsonToConfigObject(const nlohmann::json& j)
    {
        if (auto it = j.find("features"); it != j.end())  { fromJson(*it, m_config.features); }
        if (auto it = j.find("userspace"); it != j.end()) { fromJson(*it, m_config.userspace); }
        if (auto it = j.find("kernel"); it != j.end())    { fromJson(*it, m_config.kernel); }

        if (auto it = j.find("rules"); it != j.end() && it->is_object()) {
            RulesParser rules_parser;
            m_config.rules_config = rules_parser.parse_json_to_rules_config(*it);
        }
    }

    void ConfigParser::fromJson(const nlohmann::json& j, FeaturesConfig& o)
    {
        if (auto it = j.find("file_monitoring"); it != j.end()) { fromJson(*it, o.file_monitoring); }
        if (auto it = j.find("network_monitoring"); it != j.end()) { fromJson(*it, o.network_monitoring); }
        if (auto it = j.find("shell_commands_monitoring"); it != j.end()) { fromJson(*it, o.shell_commands_monitoring); }
    }

    void ConfigParser::fromJson(const nlohmann::json& j, NetworkMonitoringConfig& o)
    {
        get_if_present(j, "enabled", o.enabled);
    }

    void ConfigParser::fromJson(const nlohmann::json& j, ShellCommandsMonitoringConfig& o)
    {
        get_if_present(j, "enabled", o.enabled);
    }

    void ConfigParser::fromJson(const nlohmann::json& j, FileMonitoringConfig& o)
    {
        get_if_present(j, "enabled", o.enabled);
        if (auto it = j.find("events"); it != j.end()) { fromJson(*it, o.events); }
    }

    void ConfigParser::fromJson(const nlohmann::json& j, FileMonitoringEventsConfig& o)
    {
        get_if_present(j, "chmod", o.chmod);
        get_if_present(j, "chown", o.chown);
        get_if_present(j, "file_create", o.file_create);
        get_if_present(j, "unlink", o.unlink);
        get_if_present(j, "rename", o.rename);
        get_if_present(j, "write", o.write);
        get_if_present(j, "read", o.read);
        get_if_present(j, "mkdir", o.mkdir);
        get_if_present(j, "rmdir", o.rmdir);
    }

    void ConfigParser::fromJson(const nlohmann::json& j, UserspaceConfig& o)
    {
        get_if_present(j, "max_events_queue_size", o.max_events_queue_size);
        get_if_present(j, "set_limits", o.set_limits);
        if (auto it = j.find("output_type"); it != j.end()) {o.output_type = get_enum<OutputType>(*it);}
        if (auto it = j.find("log_level"); it != j.end()) {o.log_level = get_enum<log_level>(*it);}
        get_if_present(j, "log_location", o.log_location);
    }

    void ConfigParser::fromJson(const nlohmann::json& j, KernelConfig& o)
    {
        if (auto it = j.find("log_level"); it != j.end()) {o.log_level = get_enum<log_level>(*it);}
    }
}