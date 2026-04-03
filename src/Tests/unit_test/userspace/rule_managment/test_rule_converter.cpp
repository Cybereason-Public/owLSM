#include <gtest/gtest.h>
#include "rules_managment/rule_converter.hpp"
#include "configuration/rule.hpp"
#include <cstring>
#include <arpa/inet.h>

class RuleConverterTest : public ::testing::Test 
{
public:
    static token_t convertToken(const owlsm::config::Token& token) 
    {
        return owlsm::RuleStructConverter::convertToken(token);
    }
    
    static predicate_t convertPredicate(const owlsm::config::Predicate& predicate)
    {
        return owlsm::RuleStructConverter::convertPredicate(predicate);
    }
    
    static rule_string_t convertRuleString(const owlsm::config::RuleString& rule_string)
    {
        return owlsm::RuleStructConverter::convertRuleString(rule_string);
    }
    
    static rule_t convertRule(const owlsm::config::Rule& rule)
    {
        return owlsm::RuleStructConverter::convertRule(rule);
    }
    
    static rule_ip_t convertRuleIP(const owlsm::config::RuleIP& rule_ip)
    {
        return owlsm::RuleStructConverter::convertRuleIP(rule_ip);
    }
};

TEST_F(RuleConverterTest, convert_rule_string_basic)
{
    owlsm::config::RuleString cpp_string;
    cpp_string.value = "test_string";
    cpp_string.string_type = STRING_TYPE_CONTAINS;
    
    rule_string_t c_string = RuleConverterTest::convertRuleString(cpp_string);
    
    EXPECT_EQ(c_string.length, 11);
    EXPECT_EQ(std::string(c_string.value, c_string.length), "test_string");
    EXPECT_EQ(c_string.idx_to_DFA, -1); // Not set yet, will be set during DFA building
}

TEST_F(RuleConverterTest, convert_rule_string_empty)
{
    owlsm::config::RuleString cpp_string;
    cpp_string.value = "";
    cpp_string.string_type = STRING_TYPE_DEFAULT;
    
    rule_string_t c_string = RuleConverterTest::convertRuleString(cpp_string);
    
    EXPECT_EQ(c_string.length, 0);
    EXPECT_EQ(c_string.idx_to_DFA, -1);
}

TEST_F(RuleConverterTest, convert_rule_string_too_long_string)
{
    owlsm::config::RuleString cpp_string;
    cpp_string.value = std::string(MAX_RULE_STR_LENGTH + 1, 'a');
    cpp_string.string_type = STRING_TYPE_CONTAINS;
    
    EXPECT_ANY_THROW(RuleConverterTest::convertRuleString(cpp_string));   
}

TEST_F(RuleConverterTest, convert_predicate_with_string)
{
    owlsm::config::Predicate cpp_pred;
    cpp_pred.field = PROCESS_FILE_PATH;
    cpp_pred.comparison_type = COMPARISON_TYPE_CONTAINS;
    cpp_pred.string_idx = 5;
    cpp_pred.numerical_value = -1;
    cpp_pred.fieldref = FIELD_TYPE_NONE;
    
    predicate_t c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    
    EXPECT_EQ(c_pred.field, PROCESS_FILE_PATH);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_CONTAINS);
    EXPECT_EQ(c_pred.string_idx, 5);
    EXPECT_EQ(c_pred.numerical_value, -1);
    EXPECT_EQ(c_pred.fieldref, FIELD_TYPE_NONE);
}

TEST_F(RuleConverterTest, convert_predicate_with_numerical_value)
{
    owlsm::config::Predicate cpp_pred;
    cpp_pred.field = PROCESS_EUID;
    cpp_pred.comparison_type = COMPARISON_TYPE_EQUAL;
    cpp_pred.string_idx = -1;
    cpp_pred.numerical_value = 1000;
    cpp_pred.fieldref = FIELD_TYPE_NONE;
    
    predicate_t c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    
    EXPECT_EQ(c_pred.field, PROCESS_EUID);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_EQUAL);
    EXPECT_EQ(c_pred.string_idx, -1);
    EXPECT_EQ(c_pred.numerical_value, 1000);
    EXPECT_EQ(c_pred.fieldref, FIELD_TYPE_NONE);
}

TEST_F(RuleConverterTest, convert_predicate_with_fieldref)
{
    owlsm::config::Predicate cpp_pred;
    cpp_pred.field = PROCESS_FILE_PATH;
    cpp_pred.comparison_type = COMPARISON_TYPE_EXACT_MATCH;
    cpp_pred.string_idx = -1;
    cpp_pred.numerical_value = -1;
    cpp_pred.fieldref = PARENT_PROCESS_FILE_PATH;
    
    predicate_t c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    
    EXPECT_EQ(c_pred.field, PROCESS_FILE_PATH);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_EXACT_MATCH);
    EXPECT_EQ(c_pred.string_idx, -1);
    EXPECT_EQ(c_pred.numerical_value, -1);
    EXPECT_EQ(c_pred.fieldref, PARENT_PROCESS_FILE_PATH);
}

TEST_F(RuleConverterTest, convert_predicate_comparison_types)
{
    owlsm::config::Predicate cpp_pred;
    cpp_pred.field = PROCESS_PID;
    cpp_pred.string_idx = -1;
    cpp_pred.numerical_value = 100;
    
    // Test EQUAL
    cpp_pred.comparison_type = COMPARISON_TYPE_EQUAL;
    predicate_t c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_EQUAL);
    
    // Test ABOVE
    cpp_pred.comparison_type = COMPARISON_TYPE_ABOVE;
    c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_ABOVE);
    
    // Test BELOW
    cpp_pred.comparison_type = COMPARISON_TYPE_BELOW;
    c_pred = RuleConverterTest::convertPredicate(cpp_pred);
    EXPECT_EQ(c_pred.operation, COMPARISON_TYPE_BELOW);
}

TEST_F(RuleConverterTest, convert_token_predicate)
{
    owlsm::config::Token cpp_token;
    cpp_token.operator_type = OPERATOR_PREDICATE;
    cpp_token.predicate_idx = 10;
    
    token_t c_token = RuleConverterTest::convertToken(cpp_token);
    
    EXPECT_EQ(c_token.operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_token.pred_idx, 10);
    EXPECT_EQ(c_token.result, TOKEN_RESULT_UNKNOWN);
}

TEST_F(RuleConverterTest, convert_token_and_operator)
{
    owlsm::config::Token cpp_token;
    cpp_token.operator_type = OPERATOR_AND;
    cpp_token.predicate_idx = -1;
    
    token_t c_token = RuleConverterTest::convertToken(cpp_token);
    
    EXPECT_EQ(c_token.operator_type, OPERATOR_AND);
    EXPECT_EQ(c_token.pred_idx, -1);
    EXPECT_EQ(c_token.result, TOKEN_RESULT_UNKNOWN);
}

TEST_F(RuleConverterTest, convert_token_or_operator)
{
    owlsm::config::Token cpp_token;
    cpp_token.operator_type = OPERATOR_OR;
    cpp_token.predicate_idx = -1;
    
    token_t c_token = RuleConverterTest::convertToken(cpp_token);
    
    EXPECT_EQ(c_token.operator_type, OPERATOR_OR);
    EXPECT_EQ(c_token.pred_idx, -1);
}

TEST_F(RuleConverterTest, convert_token_not_operator)
{
    owlsm::config::Token cpp_token;
    cpp_token.operator_type = OPERATOR_NOT;
    cpp_token.predicate_idx = -1;
    
    token_t c_token = RuleConverterTest::convertToken(cpp_token);
    
    EXPECT_EQ(c_token.operator_type, OPERATOR_NOT);
    EXPECT_EQ(c_token.pred_idx, -1);
}

TEST_F(RuleConverterTest, convert_rule_basic)
{
    owlsm::config::Rule cpp_rule;
    cpp_rule.id = 42;
    cpp_rule.action = BLOCK_EVENT;
    
    // Add some tokens
    owlsm::config::Token token1;
    token1.operator_type = OPERATOR_PREDICATE;
    token1.predicate_idx = 5;
    cpp_rule.tokens.push_back(token1);
    
    owlsm::config::Token token2;
    token2.operator_type = OPERATOR_PREDICATE;
    token2.predicate_idx = 6;
    cpp_rule.tokens.push_back(token2);
    
    owlsm::config::Token token3;
    token3.operator_type = OPERATOR_AND;
    token3.predicate_idx = -1;
    cpp_rule.tokens.push_back(token3);
    cpp_rule.is_end_of_rules = false;

    rule_t c_rule = RuleConverterTest::convertRule(cpp_rule);
    
    EXPECT_EQ(c_rule.id, 42);
    EXPECT_EQ(c_rule.action, BLOCK_EVENT);
    EXPECT_EQ(c_rule.token_count, 3);
    EXPECT_EQ(c_rule.is_end_of_rules, false);
    
    // Check tokens
    EXPECT_EQ(c_rule.tokens[0].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[0].pred_idx, 5);
    
    EXPECT_EQ(c_rule.tokens[1].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[1].pred_idx, 6);
    
    EXPECT_EQ(c_rule.tokens[2].operator_type, OPERATOR_AND);
    EXPECT_EQ(c_rule.tokens[2].pred_idx, -1);
}

TEST_F(RuleConverterTest, convert_rule_is_end_of_rules_flag)
{
    owlsm::config::Rule cpp_rule;
    cpp_rule.id = 100;
    cpp_rule.action = ALLOW_EVENT;
    
    cpp_rule.is_end_of_rules = false;
    rule_t c_rule = RuleConverterTest::convertRule(cpp_rule);
    EXPECT_EQ(c_rule.is_end_of_rules, false);
    
    cpp_rule.is_end_of_rules = true;
    c_rule = RuleConverterTest::convertRule(cpp_rule);
    EXPECT_EQ(c_rule.is_end_of_rules, true);
}

TEST_F(RuleConverterTest, convert_rule_too_many_tokens)
{
    owlsm::config::Rule cpp_rule;
    cpp_rule.id = 1;
    cpp_rule.action = ALLOW_EVENT;
    
    for (int i = 0; i < MAX_TOKENS_PER_RULE + 1; i++)
    {
        owlsm::config::Token token;
        token.operator_type = OPERATOR_PREDICATE;
        token.predicate_idx = i;
        cpp_rule.tokens.push_back(token);
    }
    
    cpp_rule.is_end_of_rules = false;
    EXPECT_ANY_THROW(RuleConverterTest::convertRule(cpp_rule));
}

TEST_F(RuleConverterTest, convert_rule_empty_tokens)
{
    owlsm::config::Rule cpp_rule;
    cpp_rule.id = 50;
    cpp_rule.action = ALLOW_EVENT;
    cpp_rule.is_end_of_rules = false;
    rule_t c_rule = RuleConverterTest::convertRule(cpp_rule);
    EXPECT_EQ(c_rule.id, 50);
    EXPECT_EQ(c_rule.action, ALLOW_EVENT);
    EXPECT_EQ(c_rule.token_count, 0);
}

TEST_F(RuleConverterTest, convert_rule_complex_expression)
{
    // Test a more complex rule: (pred1 AND pred2) OR (pred3 AND NOT pred4)
    // Postfix: pred1 pred2 AND pred3 pred4 NOT AND OR
    
    owlsm::config::Rule cpp_rule;
    cpp_rule.id = 200;
    cpp_rule.action = BLOCK_EVENT;
    
    // pred1
    owlsm::config::Token t1;
    t1.operator_type = OPERATOR_PREDICATE;
    t1.predicate_idx = 1;
    cpp_rule.tokens.push_back(t1);
    
    // pred2
    owlsm::config::Token t2;
    t2.operator_type = OPERATOR_PREDICATE;
    t2.predicate_idx = 2;
    cpp_rule.tokens.push_back(t2);
    
    // AND
    owlsm::config::Token t3;
    t3.operator_type = OPERATOR_AND;
    t3.predicate_idx = -1;
    cpp_rule.tokens.push_back(t3);
    
    // pred3
    owlsm::config::Token t4;
    t4.operator_type = OPERATOR_PREDICATE;
    t4.predicate_idx = 3;
    cpp_rule.tokens.push_back(t4);
    
    // pred4
    owlsm::config::Token t5;
    t5.operator_type = OPERATOR_PREDICATE;
    t5.predicate_idx = 4;
    cpp_rule.tokens.push_back(t5);
    
    // NOT
    owlsm::config::Token t6;
    t6.operator_type = OPERATOR_NOT;
    t6.predicate_idx = -1;
    cpp_rule.tokens.push_back(t6);
    
    // AND
    owlsm::config::Token t7;
    t7.operator_type = OPERATOR_AND;
    t7.predicate_idx = -1;
    cpp_rule.tokens.push_back(t7);
    
    // OR
    owlsm::config::Token t8;
    t8.operator_type = OPERATOR_OR;
    t8.predicate_idx = -1;
    cpp_rule.tokens.push_back(t8);
    cpp_rule.is_end_of_rules = false;
    
    rule_t c_rule = RuleConverterTest::convertRule(cpp_rule);
    
    EXPECT_EQ(c_rule.id, 200);
    EXPECT_EQ(c_rule.action, BLOCK_EVENT);
    EXPECT_EQ(c_rule.token_count, 8);
    
    // Verify the postfix expression
    EXPECT_EQ(c_rule.tokens[0].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[0].pred_idx, 1);
    
    EXPECT_EQ(c_rule.tokens[1].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[1].pred_idx, 2);
    
    EXPECT_EQ(c_rule.tokens[2].operator_type, OPERATOR_AND);
    
    EXPECT_EQ(c_rule.tokens[3].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[3].pred_idx, 3);
    
    EXPECT_EQ(c_rule.tokens[4].operator_type, OPERATOR_PREDICATE);
    EXPECT_EQ(c_rule.tokens[4].pred_idx, 4);
    
    EXPECT_EQ(c_rule.tokens[5].operator_type, OPERATOR_NOT);
    
    EXPECT_EQ(c_rule.tokens[6].operator_type, OPERATOR_AND);
    
    EXPECT_EQ(c_rule.tokens[7].operator_type, OPERATOR_OR);
}

TEST_F(RuleConverterTest, convert_rule_ip_ipv4_exact)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "192.168.1.100";
    cpp_ip.cidr = 32;
    cpp_ip.ip_type = AF_INET;
    
    rule_ip_t c_ip = RuleConverterTest::convertRuleIP(cpp_ip);
    
    // 192.168.1.100 in network byte order: 0x6401A8C0
    EXPECT_EQ(c_ip.ip[0], htonl(0xC0A80164));
    EXPECT_EQ(c_ip.ip[1], 0);
    EXPECT_EQ(c_ip.ip[2], 0);
    EXPECT_EQ(c_ip.ip[3], 0);
    
    // /32 mask = 0xFFFFFFFF
    EXPECT_EQ(c_ip.cidr_mask[0], htonl(0xFFFFFFFF));
}

TEST_F(RuleConverterTest, convert_rule_ip_ipv4_cidr24)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "10.0.0.0";
    cpp_ip.cidr = 24;
    cpp_ip.ip_type = AF_INET;
    
    rule_ip_t c_ip = RuleConverterTest::convertRuleIP(cpp_ip);
    
    // 10.0.0.0 in network byte order
    EXPECT_EQ(c_ip.ip[0], htonl(0x0A000000));
    
    // /24 mask = 0xFFFFFF00
    EXPECT_EQ(c_ip.cidr_mask[0], htonl(0xFFFFFF00));
}

TEST_F(RuleConverterTest, convert_rule_ip_ipv4_cidr0)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "0.0.0.0";
    cpp_ip.cidr = 0;
    cpp_ip.ip_type = AF_INET;
    
    rule_ip_t c_ip = RuleConverterTest::convertRuleIP(cpp_ip);
    
    // /0 mask = 0x00000000 (match all)
    EXPECT_EQ(c_ip.cidr_mask[0], 0);
}

TEST_F(RuleConverterTest, convert_rule_ip_ipv6_exact)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "2001:0db8:0000:0000:0000:0000:0000:0001";
    cpp_ip.cidr = 128;
    cpp_ip.ip_type = AF_INET6;
    
    rule_ip_t c_ip = RuleConverterTest::convertRuleIP(cpp_ip);
    
    // All mask bits set for /128
    EXPECT_EQ(c_ip.cidr_mask[0], 0xFFFFFFFF);
    EXPECT_EQ(c_ip.cidr_mask[1], 0xFFFFFFFF);
    EXPECT_EQ(c_ip.cidr_mask[2], 0xFFFFFFFF);
    EXPECT_EQ(c_ip.cidr_mask[3], 0xFFFFFFFF);
}

TEST_F(RuleConverterTest, convert_rule_ip_ipv6_cidr64)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "2001:db8::";
    cpp_ip.cidr = 64;
    cpp_ip.ip_type = AF_INET6;
    
    rule_ip_t c_ip = RuleConverterTest::convertRuleIP(cpp_ip);
    
    // /64 mask: first 64 bits set
    EXPECT_EQ(c_ip.cidr_mask[0], 0xFFFFFFFF);
    EXPECT_EQ(c_ip.cidr_mask[1], 0xFFFFFFFF);
    EXPECT_EQ(c_ip.cidr_mask[2], 0);
    EXPECT_EQ(c_ip.cidr_mask[3], 0);
}

TEST_F(RuleConverterTest, convert_rule_ip_invalid_ipv4)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "invalid_ip";
    cpp_ip.cidr = 32;
    cpp_ip.ip_type = AF_INET;
    
    EXPECT_ANY_THROW(RuleConverterTest::convertRuleIP(cpp_ip));
}

TEST_F(RuleConverterTest, convert_rule_ip_invalid_ipv6)
{
    owlsm::config::RuleIP cpp_ip;
    cpp_ip.ip = "invalid_ip";
    cpp_ip.cidr = 128;
    cpp_ip.ip_type = AF_INET6;
    
    EXPECT_ANY_THROW(RuleConverterTest::convertRuleIP(cpp_ip));
}