#include "dfa.bpf.h"
#include "common_maps.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"

__noinline int kmp_dfa_search(const struct string_utils_ctx *sctx)
{
    if(!sctx)
    {
        return FALSE;
    }

    if (sctx->needle_length == 0 || sctx->needle_length > sctx->haystack_length || sctx->idx_to_DFA < 0) 
    {
        return FALSE;
    }

    unsigned int dfa_key = (unsigned int)sctx->idx_to_DFA;
    struct flat_2d_dfa_array_t *dfa = bpf_map_lookup_elem(&idx_to_DFA_map, &dfa_key);
    if (!dfa) 
    {
        return FALSE;
    }

    unsigned int state = 0;
    unsigned int match_state = sctx->needle_length;
    for (int i = 0; i < sctx->haystack_length && i < PATH_MAX; i++) 
    {
        unsigned int c = (unsigned char)sctx->haystack[i];
        unsigned int idx = (state * DFA_ALPHABET_SIZE) + c;
        if(idx >= 0 && idx < DFA_TOTAL_SIZE)
        {
            state = dfa->value[idx];
        }

        if (state == match_state) 
        {
            return TRUE;
        }
    }

    return FALSE;
}

__noinline int regex_dfa_search(const struct string_utils_ctx *sctx)
{
    if (!sctx)
    {
        return FALSE;
    }

    if (sctx->idx_to_DFA < 0)
    {
        return FALSE;
    }

    unsigned int dfa_key = (unsigned int)sctx->idx_to_DFA;
    struct flat_2d_dfa_array_t *dfa = bpf_map_lookup_elem(&idx_to_DFA_map, &dfa_key);
    if (!dfa)
    {
        return FALSE;
    }

    unsigned long long *accepting_states = bpf_map_lookup_elem(&idx_to_accepting_states_map, &dfa_key);
    if (!accepting_states)
    {
        return FALSE;
    }

    unsigned int state = 1;
    for (int i = 0; i < sctx->haystack_length && i < PATH_MAX; i++)
    {
        unsigned int c = (unsigned char)sctx->haystack[i];
        unsigned int idx = (state * DFA_ALPHABET_SIZE) + c;
        if (idx < DFA_TOTAL_SIZE)
        {
            state = dfa->value[idx];
        }

        if (state < MAX_REGEX_DFA_STATES && ((*accepting_states >> state) & 1))
        {
            return TRUE;
        }
    }

    return FALSE;
}