#pragma once
#include "events_structs.h"
#include "rules_structs.h"

struct string_utils_test {
    int id;
    enum comparison_type test_type;
    char haystack[PATH_MAX];
    unsigned char haystack_length;
    char needle[PATH_MAX];
    unsigned char needle_length;

    int  expected_result;
    int  actual_result;       
};

struct struct_extractors_test
{
    char path_to_find[PATH_MAX];
    char cmd_to_find[CMD_MAX];
    unsigned char cmd_length;
    int dfa_id;
    int found;
};

struct get_cmd_from_user_argv_test
{
    char expected[CMD_MAX]; // expected reconstructed command line (null-terminated)
    short expected_length;  // without null character
    int found;
};

enum process_cache_operations {
    UPDATE_ENTRY,
    GET_ENTRY,
    DELETE_ENTRY,
};

struct process_cache_test
{
    struct process_t process;
    enum process_cache_operations operation;
};

struct chmod_event_and_rule_matcher_test {
    struct event_t event;
    struct rule_t  rule;
    int  actual_result;
};

struct prevention_test{ 
    unsigned long long process_start_time;
    int result;
};