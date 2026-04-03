#include <gtest/gtest.h>
#include "configuration/rules_parser.hpp"
#include "raii_temp_files.hpp"

#include <3rd_party/nlohmann/json.hpp>

class RulesParserNewTest : public ::testing::Test {};

constexpr std::string_view MINIMAL_RULES_JSON = R"({
  "id_to_string": {
    "0": {
      "value": "test_string",
      "string_type": 1
    }
  },
  "id_to_predicate": {
    "0": {
      "field": "target.file.path",
      "comparison_type": "contains",
      "string_idx": 0,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "rules": [
    {
      "id": 1,
      "description": "Test rule",
      "action": "BLOCK_EVENT",
      "applied_events": ["READ"],
      "tokens": [
        {
          "operator_type": "OPERATOR_PREDICATE",
          "predicate_idx": 0
        }
      ]
    }
  ]
})";

constexpr std::string_view COMPLEX_RULES_JSON = R"({
  "id_to_string": {
    "0": {
      "value": ".ssh/id_rsa",
      "string_type": 1
    },
    "1": {
      "value": "curl",
      "string_type": 0
    }
  },
  "id_to_predicate": {
    "0": {
      "field": "target.file.path",
      "comparison_type": "contains",
      "string_idx": 0,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "1": {
      "field": "process.file.filename",
      "comparison_type": "endswith",
      "string_idx": 1,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "2": {
      "field": "process.pid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "rules": [
    {
      "id": 100,
      "description": "Detect unauthorized SSH private key access",
      "action": "BLOCK_EVENT",
      "min_version": "0.0.1",
      "max_version": "1.0.0",
      "applied_events": ["READ", "WRITE"],
      "tokens": [
        {
          "operator_type": "OPERATOR_PREDICATE",
          "predicate_idx": 0
        },
        {
          "operator_type": "OPERATOR_PREDICATE",
          "predicate_idx": 1
        },
        {
          "operator_type": "OPERATOR_AND"
        },
        {
          "operator_type": "OPERATOR_PREDICATE",
          "predicate_idx": 2
        },
        {
          "operator_type": "OPERATOR_NOT"
        },
        {
          "operator_type": "OPERATOR_AND"
        }
      ]
    }
  ]
})";

TEST_F(RulesParserNewTest, parse_minimal_rules_config)
{
    nlohmann::json j = nlohmann::json::parse(MINIMAL_RULES_JSON);
    owlsm::config::RulesParser parser;
    
    EXPECT_NO_THROW({
        auto config = parser.parse_json_to_rules_config(j);
        
        // Check id_to_string
        EXPECT_EQ(config.id_to_string.size(), 1);
        EXPECT_EQ(config.id_to_string[0].value, "test_string");
        EXPECT_EQ(config.id_to_string[0].string_type, STRING_TYPE_CONTAINS);
        
        // Check id_to_predicate
        EXPECT_EQ(config.id_to_predicate.size(), 1);
        EXPECT_EQ(config.id_to_predicate[0].field, TARGET_FILE_PATH);
        EXPECT_EQ(config.id_to_predicate[0].comparison_type, COMPARISON_TYPE_CONTAINS);
        EXPECT_EQ(config.id_to_predicate[0].string_idx, 0);
        EXPECT_EQ(config.id_to_predicate[0].numerical_value, -1);
        EXPECT_EQ(config.id_to_predicate[0].fieldref, FIELD_TYPE_NONE);
        
        // Check rules
        EXPECT_EQ(config.rules.size(), 1);
        EXPECT_EQ(config.rules[0].id, 1);
        EXPECT_EQ(config.rules[0].action, BLOCK_EVENT);
        EXPECT_EQ(config.rules[0].metadata.description, "Test rule");
        EXPECT_EQ(config.rules[0].applied_events.size(), 1);
        EXPECT_EQ(config.rules[0].applied_events[0], READ);
        EXPECT_EQ(config.rules[0].tokens.size(), 1);
        EXPECT_EQ(config.rules[0].tokens[0].operator_type, OPERATOR_PREDICATE);
        EXPECT_EQ(config.rules[0].tokens[0].predicate_idx, 0);
    });
}

TEST_F(RulesParserNewTest, parse_complex_rules_config)
{
    nlohmann::json j = nlohmann::json::parse(COMPLEX_RULES_JSON);
    owlsm::config::RulesParser parser;
    
    using Version = semver::version<int, int, int>;
    
    EXPECT_NO_THROW({
        auto config = parser.parse_json_to_rules_config(j);
        
        // Check id_to_string
        EXPECT_EQ(config.id_to_string.size(), 2);
        EXPECT_EQ(config.id_to_string[0].value, ".ssh/id_rsa");
        EXPECT_EQ(config.id_to_string[0].string_type, STRING_TYPE_CONTAINS);
        EXPECT_EQ(config.id_to_string[1].value, "curl");
        EXPECT_EQ(config.id_to_string[1].string_type, STRING_TYPE_DEFAULT);
        
        // Check id_to_predicate
        EXPECT_EQ(config.id_to_predicate.size(), 3);
        EXPECT_EQ(config.id_to_predicate[0].field, TARGET_FILE_PATH);
        EXPECT_EQ(config.id_to_predicate[0].fieldref, FIELD_TYPE_NONE);
        EXPECT_EQ(config.id_to_predicate[1].field, PROCESS_FILE_FILENAME);
        EXPECT_EQ(config.id_to_predicate[1].fieldref, FIELD_TYPE_NONE);
        EXPECT_EQ(config.id_to_predicate[2].field, PROCESS_PID);
        EXPECT_EQ(config.id_to_predicate[2].comparison_type, COMPARISON_TYPE_EQUAL);
        EXPECT_EQ(config.id_to_predicate[2].string_idx, -1);
        EXPECT_EQ(config.id_to_predicate[2].numerical_value, 1000);
        EXPECT_EQ(config.id_to_predicate[2].fieldref, FIELD_TYPE_NONE);
        
        // Check rules
        EXPECT_EQ(config.rules.size(), 1);
        EXPECT_EQ(config.rules[0].id, 100);
        EXPECT_EQ(config.rules[0].action, BLOCK_EVENT);
        EXPECT_EQ(config.rules[0].metadata.description, "Detect unauthorized SSH private key access");
        
        // Check applied_events
        EXPECT_EQ(config.rules[0].applied_events.size(), 2);
        EXPECT_EQ(config.rules[0].applied_events[0], READ);
        EXPECT_EQ(config.rules[0].applied_events[1], WRITE);
        
        // Check tokens
        EXPECT_EQ(config.rules[0].tokens.size(), 6);
        EXPECT_EQ(config.rules[0].tokens[0].operator_type, OPERATOR_PREDICATE);
        EXPECT_EQ(config.rules[0].tokens[0].predicate_idx, 0);
        EXPECT_EQ(config.rules[0].tokens[1].operator_type, OPERATOR_PREDICATE);
        EXPECT_EQ(config.rules[0].tokens[1].predicate_idx, 1);
        EXPECT_EQ(config.rules[0].tokens[2].operator_type, OPERATOR_AND);
        EXPECT_EQ(config.rules[0].tokens[2].predicate_idx, -1);
        EXPECT_EQ(config.rules[0].tokens[3].operator_type, OPERATOR_PREDICATE);
        EXPECT_EQ(config.rules[0].tokens[4].operator_type, OPERATOR_NOT);
        EXPECT_EQ(config.rules[0].tokens[5].operator_type, OPERATOR_AND);
        
        // Check versions
        Version min_version;
        Version max_version;
        semver::parse("0.0.1", min_version);
        semver::parse("1.0.0", max_version);
        EXPECT_EQ(config.rules[0].min_version, min_version);
        EXPECT_EQ(config.rules[0].max_version, max_version);
    });
}

TEST_F(RulesParserNewTest, parse_field_id_transformation)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {
            "0": {
                "field": "process.file.owner.uid",
                "comparison_type": "equal",
                "string_idx": -1,
                "numerical_value": 0,
                "fieldref": "FIELD_TYPE_NONE"
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_predicate[0].field, PROCESS_FILE_OWNER_UID);
}

TEST_F(RulesParserNewTest, parse_comparison_type_transformation)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {
            "0": {
                "field": "process.pid",
                "comparison_type": "equal_above",
                "string_idx": -1,
                "numerical_value": 100,
                "fieldref": "FIELD_TYPE_NONE"
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_predicate[0].comparison_type, COMPARISON_TYPE_EQUAL_ABOVE);
}

TEST_F(RulesParserNewTest, invalid_field_throws_exception)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {
            "0": {
                "field": "invalid.field.name",
                "comparison_type": "equal",
                "string_idx": -1,
                "numerical_value": 0,
                "fieldref": "FIELD_TYPE_NONE"
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    EXPECT_THROW(parser.parse_json_to_rules_config(j), std::runtime_error);
}

TEST_F(RulesParserNewTest, invalid_comparison_type_throws_exception)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {
            "0": {
                "field": "process.pid",
                "comparison_type": "invalid_comparison",
                "string_idx": -1,
                "numerical_value": 0,
                "fieldref": "FIELD_TYPE_NONE"
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    EXPECT_THROW(parser.parse_json_to_rules_config(j), std::runtime_error);
}

TEST_F(RulesParserNewTest, invalid_operator_type_throws_exception)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["READ"],
                "tokens": [
                    {
                        "operator_type": "INVALID_OPERATOR"
                    }
                ]
            }
        ]
    })");
    
    owlsm::config::RulesParser parser;
    EXPECT_THROW(parser.parse_json_to_rules_config(j), std::runtime_error);
}

TEST_F(RulesParserNewTest, invalid_event_type_throws_exception)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["INVALID_EVENT"],
                "tokens": []
            }
        ]
    })");
    
    owlsm::config::RulesParser parser;
    EXPECT_THROW(parser.parse_json_to_rules_config(j), std::runtime_error);
}

TEST_F(RulesParserNewTest, parse_id_to_ip_ipv4)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "id_to_ip": {
            "0": {
                "ip": "192.168.1.0",
                "cidr": 24,
                "ip_type": 2
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_ip.size(), 1);
    EXPECT_EQ(config.id_to_ip[0].ip, "192.168.1.0");
    EXPECT_EQ(config.id_to_ip[0].cidr, 24);
    EXPECT_EQ(config.id_to_ip[0].ip_type, AF_INET);
}

TEST_F(RulesParserNewTest, parse_id_to_ip_ipv6)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "id_to_ip": {
            "0": {
                "ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
                "cidr": 64,
                "ip_type": 10
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_ip.size(), 1);
    EXPECT_EQ(config.id_to_ip[0].ip, "2001:0db8:0000:0000:0000:0000:0000:0001");
    EXPECT_EQ(config.id_to_ip[0].cidr, 64);
    EXPECT_EQ(config.id_to_ip[0].ip_type, AF_INET6);
}

TEST_F(RulesParserNewTest, parse_id_to_ip_multiple_entries)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "id_to_ip": {
            "0": {
                "ip": "10.0.0.0",
                "cidr": 8,
                "ip_type": 2
            },
            "1": {
                "ip": "192.168.0.1",
                "cidr": 32,
                "ip_type": 2
            }
        },
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_ip.size(), 2);
    EXPECT_EQ(config.id_to_ip[0].ip, "10.0.0.0");
    EXPECT_EQ(config.id_to_ip[0].cidr, 8);
    EXPECT_EQ(config.id_to_ip[1].ip, "192.168.0.1");
    EXPECT_EQ(config.id_to_ip[1].cidr, 32);
}

TEST_F(RulesParserNewTest, parse_empty_id_to_ip)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "id_to_ip": {},
        "rules": []
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.id_to_ip.size(), 0);
}

TEST_F(RulesParserNewTest, parse_network_event_type)
{
    nlohmann::json j = nlohmann::json::parse(R"({
        "id_to_string": {},
        "id_to_predicate": {},
        "id_to_ip": {},
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["NETWORK"],
                "tokens": []
            }
        ]
    })");
    
    owlsm::config::RulesParser parser;
    auto config = parser.parse_json_to_rules_config(j);
    
    EXPECT_EQ(config.rules.size(), 1);
    EXPECT_EQ(config.rules[0].applied_events.size(), 1);
    EXPECT_EQ(config.rules[0].applied_events[0], NETWORK);
}