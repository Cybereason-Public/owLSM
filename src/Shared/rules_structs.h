#pragma once
#include "events_structs.h"

#define MAX_RULE_STR_LENGTH MAX_NEEDLE_LENGTH

enum token_result {
    TOKEN_RESULT_UNKNOWN = 0,
    TOKEN_RESULT_TRUE = 1,
    TOKEN_RESULT_FALSE = 2
};

struct rule_string_t {
    char value[MAX_RULE_STR_LENGTH]; 
    unsigned char length;
    int idx_to_DFA;
};

struct rule_ip_t {
    unsigned int ip[4];
    unsigned int cidr_mask[4];
};

struct predicate_t {
    enum rule_field_type field;
    enum comparison_type operation;
    int string_idx;
    int numerical_value;
    enum rule_field_type fieldref;
};

struct token_t {
    enum operator_types operator_type;
    int pred_idx;
    enum token_result result;
};

struct predicate_result_t {
    enum token_result result;
    unsigned long long time;
};

struct rule_t {
    unsigned int id;
    enum rule_action action;
    unsigned char token_count;
    unsigned char is_end_of_rules;
    struct token_t tokens[MAX_TOKENS_PER_RULE];
};

#define DFA_NUM_STATES (MAX_RULE_STR_LENGTH + 1) 
#define DFA_ALPHABET_SIZE 256
#define DFA_TOTAL_SIZE (DFA_NUM_STATES * DFA_ALPHABET_SIZE)
struct flat_2d_dfa_array_t {
    unsigned char value[DFA_TOTAL_SIZE];
};