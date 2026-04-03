#include "shared_unit_tests_structs_definitions.h"
#include "string_utils.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct string_utils_test);
} test_string_utils_map SEC(".maps");


SEC("raw_tp")
int test_string_utils_program(struct __sk_buff *skb)
{
    u32 key = 0;
    struct string_utils_test *t = bpf_map_lookup_elem(&test_string_utils_map, &key);
    if (!t)
    {
        return 0;
    }

    struct string_utils_ctx *sctx = string_utils_setup(t->haystack, t->needle, t->haystack_length, t->needle_length, PATH_MAX);
    if(!sctx)
    {
        return 0;
    }

    sctx->idx_to_DFA = t->id;
    sctx->comparison_type = t->test_type;

    switch (sctx->comparison_type) 
    {
        case COMPARISON_TYPE_EXACT_MATCH: 
            t->actual_result = string_exact_match(sctx);
            break;
        case COMPARISON_TYPE_CONTAINS: 
            t->actual_result = string_contains(sctx);
            break;
        case COMPARISON_TYPE_STARTS_WITH: 
            t->actual_result = starts_with(sctx);
            break;
        case COMPARISON_TYPE_ENDS_WITH: 
            t->actual_result = ends_with(sctx);
            break;
        case COMPARISON_TYPE_REGEX:
            t->actual_result = regex_dfa_search(sctx);
            break;
        default:
            t->actual_result = FALSE;
            break;
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
