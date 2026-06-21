#pragma once
#include "bpf_header_includes.h"
#include "rules_structs.h"

#define MAX_PERCPU_ARRAY_SIZE 1024

struct ebpf_features {
    bool chown_hook_available;
    bool ringbuffer_map_value_available;
};

struct printed_message {
    char value[512];
};

struct string_buffer {
        unsigned char data[MAX_PERCPU_ARRAY_SIZE];
};

struct string_utils_ctx
{
    unsigned char haystack_max_length;
    unsigned char haystack_length;
    char haystack[PATH_MAX];
    unsigned char needle_max_length;
    unsigned char needle_length;
    char needle[PATH_MAX];
    enum comparison_type comparison_type;
    int idx_to_DFA;
};

struct eval_stack {
    struct token_t tokens[MAX_TOKENS_PER_RULE];
    unsigned char stack_pointer;
};
