#include <gtest/gtest.h>
#include "config_parser.hpp"
#include "configuration/config_parser.hpp"
#include "json_and_schemas_examples.hpp"
#include "raii_temp_files.hpp"
#include "configuration/schema.inc"

#include <stdexcept>
#include <semver/semver_wrapper.hpp>

class ConfigParserTest : public ::testing::Test 
{
public:
    static nlohmann::json createJsonObjectFromFile(const std::string& filepath)
    {
        auto config_parser = createParser();
        return config_parser.createJsonObjectFromFile(filepath);
    }

    static void validateJsonAgainstSchema(const nlohmann::json& json, const nlohmann::json& schema)
    {
        auto config_parser = createParser();
        config_parser.validateJsonAgainstSchema(json, schema);
    }

private:
    static owlsm::config::ConfigParser createParser()
    {
        owlsm::RaiiTempFile temp_file;
        temp_file << SHORT_VALID_JSON_3;
        return owlsm::config::ConfigParser(temp_file.getPath(), std::string(SHORT_VALID_SCHEMA_3));
    }
};

TEST_F(ConfigParserTest, createJsonObjectFromFile_invalid_json) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_SHORT_JSON_1;
    EXPECT_ANY_THROW(ConfigParserTest::createJsonObjectFromFile(temp_file.getPath()));
}

TEST_F(ConfigParserTest, createJsonObjectFromFile_empty_json) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << EMPTY_JSON_2;
    EXPECT_ANY_THROW(ConfigParserTest::createJsonObjectFromFile(temp_file.getPath()));
}

TEST_F(ConfigParserTest, createJsonObjectFromFile_valid_json) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << SHORT_VALID_JSON_3;
    EXPECT_NO_THROW(ConfigParserTest::createJsonObjectFromFile(temp_file.getPath()));
}

TEST_F(ConfigParserTest, validateJsonAgainstSchema_valid) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << SHORT_VALID_JSON_3;
    auto json = ConfigParserTest::createJsonObjectFromFile(temp_file.getPath());
    owlsm::RaiiTempFile schema_file;
    schema_file << SHORT_VALID_SCHEMA_3;
    auto schema = ConfigParserTest::createJsonObjectFromFile(schema_file.getPath());
    EXPECT_NO_THROW(ConfigParserTest::validateJsonAgainstSchema(json, schema));
}

TEST_F(ConfigParserTest, validateJsonAgainstSchema_invalid) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << SHORT_VALID_JSON_3;
    auto json = ConfigParserTest::createJsonObjectFromFile(temp_file.getPath());
    owlsm::RaiiTempFile schema_file;
    schema_file << SHORT_INVALID_SCHEMA_3;
    auto schema = ConfigParserTest::createJsonObjectFromFile(schema_file.getPath());
    EXPECT_ANY_THROW(ConfigParserTest::validateJsonAgainstSchema(json, schema));
}

TEST_F(ConfigParserTest, default_values_are_set) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << CONFIG_JSON_ONLY_FEATURES_4;
    owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4));
    auto config = parser.getConfig();
    EXPECT_TRUE(config.features.file_monitoring.enabled);
    EXPECT_TRUE(config.features.file_monitoring.events.unlink);
    EXPECT_TRUE(config.features.file_monitoring.events.chmod);
    EXPECT_TRUE(config.features.file_monitoring.events.chown);
    EXPECT_TRUE(config.features.file_monitoring.events.file_create);
    EXPECT_TRUE(config.features.file_monitoring.events.rename);
    EXPECT_TRUE(config.features.file_monitoring.events.write);
    EXPECT_TRUE(config.features.file_monitoring.events.read);
    EXPECT_TRUE(config.features.file_monitoring.events.mkdir);
    EXPECT_TRUE(config.features.file_monitoring.events.rmdir);
    EXPECT_TRUE(config.features.network_monitoring.enabled);
    EXPECT_TRUE(config.features.shell_commands_monitoring.enabled);
    EXPECT_EQ(config.userspace.max_events_queue_size, 10000);
    EXPECT_EQ(config.userspace.output_type, owlsm::config::OutputType::JSON);
    EXPECT_EQ(config.userspace.log_level, LOG_LEVEL_INFO);
    EXPECT_EQ(config.kernel.log_level, LOG_LEVEL_ERROR);
    EXPECT_TRUE(config.rules_config.rules.empty());
}

TEST_F(ConfigParserTest, real_config_is_parsed_correctly) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << REAL_JSON_5;
    owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4));
    auto config = parser.getConfig();
    
    // Check features
    EXPECT_TRUE(config.features.file_monitoring.enabled);
    EXPECT_FALSE(config.features.file_monitoring.events.unlink);
    EXPECT_TRUE(config.features.file_monitoring.events.chmod);
    EXPECT_TRUE(config.features.file_monitoring.events.read);
    EXPECT_TRUE(config.features.network_monitoring.enabled);
    EXPECT_TRUE(config.features.shell_commands_monitoring.enabled);

    // Check userspace and kernel config
    EXPECT_EQ(config.userspace.max_events_queue_size, 55);
    EXPECT_EQ(config.userspace.output_type, owlsm::config::OutputType::JSON);
    EXPECT_EQ(config.userspace.log_level, LOG_LEVEL_WARNING);
    EXPECT_EQ(config.kernel.log_level, LOG_LEVEL_DEBUG);

    // Check id_to_string
    EXPECT_EQ(config.rules_config.id_to_string.size(), 2);
    EXPECT_EQ(config.rules_config.id_to_string[0].value, ".ssh/id_rsa");
    EXPECT_TRUE(config.rules_config.id_to_string[0].is_contains);
    EXPECT_EQ(config.rules_config.id_to_string[1].value, "curl");
    EXPECT_FALSE(config.rules_config.id_to_string[1].is_contains);

    // Check id_to_predicate
    EXPECT_EQ(config.rules_config.id_to_predicate.size(), 3);
    EXPECT_EQ(config.rules_config.id_to_predicate[0].field, TARGET_FILE_PATH);
    EXPECT_EQ(config.rules_config.id_to_predicate[0].comparison_type, COMPARISON_TYPE_CONTAINS);
    EXPECT_EQ(config.rules_config.id_to_predicate[0].string_idx, 0);
    EXPECT_EQ(config.rules_config.id_to_predicate[0].numerical_value, -1);
    EXPECT_EQ(config.rules_config.id_to_predicate[0].fieldref, FIELD_TYPE_NONE);
    
    EXPECT_EQ(config.rules_config.id_to_predicate[1].field, PROCESS_FILE_FILENAME);
    EXPECT_EQ(config.rules_config.id_to_predicate[1].comparison_type, COMPARISON_TYPE_ENDS_WITH);
    EXPECT_EQ(config.rules_config.id_to_predicate[1].string_idx, 1);
    EXPECT_EQ(config.rules_config.id_to_predicate[1].numerical_value, -1);
    EXPECT_EQ(config.rules_config.id_to_predicate[1].fieldref, FIELD_TYPE_NONE);
    
    EXPECT_EQ(config.rules_config.id_to_predicate[2].field, PROCESS_PID);
    EXPECT_EQ(config.rules_config.id_to_predicate[2].comparison_type, COMPARISON_TYPE_EQUAL);
    EXPECT_EQ(config.rules_config.id_to_predicate[2].string_idx, -1);
    EXPECT_EQ(config.rules_config.id_to_predicate[2].numerical_value, 1000);
    EXPECT_EQ(config.rules_config.id_to_predicate[2].fieldref, FIELD_TYPE_NONE);

    // Check id_to_ip (empty in REAL_JSON_5)
    EXPECT_EQ(config.rules_config.id_to_ip.size(), 0);

    // Check rules
    EXPECT_EQ(config.rules_config.rules.size(), 1);
    EXPECT_EQ(config.rules_config.rules[0].id, 100);
    EXPECT_EQ(config.rules_config.rules[0].action, BLOCK_EVENT);
    EXPECT_EQ(config.rules_config.rules[0].metadata.description, "Test rule");
    
    // Check applied_events
    EXPECT_EQ(config.rules_config.rules[0].applied_events.size(), 2);
    EXPECT_EQ(config.rules_config.rules[0].applied_events[0], READ);
    EXPECT_EQ(config.rules_config.rules[0].applied_events[1], WRITE);
    
    // Check tokens
    EXPECT_EQ(config.rules_config.rules[0].tokens.size(), 6);
    EXPECT_EQ(config.rules_config.rules[0].tokens[0].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(config.rules_config.rules[0].tokens[0].predicate_idx, 0);
    EXPECT_EQ(config.rules_config.rules[0].tokens[1].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(config.rules_config.rules[0].tokens[1].predicate_idx, 1);
    EXPECT_EQ(config.rules_config.rules[0].tokens[2].operator_type, OPERATOR_AND);
    EXPECT_EQ(config.rules_config.rules[0].tokens[3].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(config.rules_config.rules[0].tokens[3].predicate_idx, 2);
    EXPECT_EQ(config.rules_config.rules[0].tokens[4].operator_type, OPERATOR_NOT);
    EXPECT_EQ(config.rules_config.rules[0].tokens[5].operator_type, OPERATOR_AND);
}

TEST_F(ConfigParserTest, string_value_too_long_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_STRING_TOO_LONG_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, is_contains_not_boolean_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_IS_CONTAINS_NOT_BOOLEAN_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, invalid_field_name_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_FIELD_NAME_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, both_indices_set_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_BOTH_INDICES_SET_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, rule_with_zero_tokens_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << RULE_WITH_ZERO_TOKENS_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, empty_id_to_predicate_fails_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << INVALID_EMPTY_ID_TO_PREDICATE_JSON;
    EXPECT_ANY_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}

TEST_F(ConfigParserTest, empty_id_to_string_passes_validation) 
{
    owlsm::RaiiTempFile temp_file;
    temp_file << VALID_EMPTY_ID_TO_STRING_JSON;
    EXPECT_NO_THROW(owlsm::config::ConfigParser parser(temp_file.getPath(), std::string(REAL_SCHEMA_4)));
}