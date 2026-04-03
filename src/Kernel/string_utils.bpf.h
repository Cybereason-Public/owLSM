#pragma once
#include "dfa.bpf.h"
#include "common_maps.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "allocators.bpf.h"

statfunc struct string_utils_ctx* string_utils_setup(const char *haystack, const char *needle, unsigned char haystack_length, unsigned char needle_length, unsigned haystack_max_length)
{
    struct string_utils_ctx *sctx = allocate_empty_string_utils_ctx();
    if(!sctx)
    {
        return NULL;
    }
    
    sctx->haystack_max_length = haystack_max_length;
    sctx->haystack_length = haystack_length;
    barrier_var(haystack_max_length);
    if(bpf_probe_read_kernel(sctx->haystack, haystack_max_length, haystack) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }

    sctx->needle_max_length = MAX_NEEDLE_LENGTH;
    sctx->needle_length = needle_length;    
    if(bpf_probe_read_kernel(sctx->needle, sctx->needle_max_length, needle) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }

    return sctx;
}


statfunc int is_needle_in_haystack_from_index(const struct string_utils_ctx *sctx, unsigned char index)
{
    if (sctx->needle_length > sctx->haystack_length - index)
    {
        return FALSE;
    }

    for (int k = 0; k < sctx->needle_max_length; k++) 
    {
        if (k == sctx->needle_length)          
        {
            return TRUE;
        }


        if (sctx->haystack[LIMIT_PATH_SIZE(index + k)] != sctx->needle[LIMIT_PATH_SIZE(k)])
        {
            return FALSE;
        }              
    }
    
    return sctx->needle_length == sctx->needle_max_length;
} 

statfunc int string_contains(const struct string_utils_ctx *sctx)
{
    return kmp_dfa_search(sctx);
}

statfunc int string_exact_match(const struct string_utils_ctx *sctx)
{
    if(sctx->needle_length != sctx->haystack_length)
    {
        return FALSE;
    }
    return is_needle_in_haystack_from_index(sctx, 0);
}

statfunc int string_exact_match_known_length(const char * a, const char * b, int length)
{
    for (int i = 0; i < length; i++)
    {
        if (a[i] != b[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}
statfunc int starts_with(const struct string_utils_ctx *sctx)
{
    if (sctx->needle_length == 0 || sctx->needle_length > sctx->haystack_length || sctx->needle_length > sctx->needle_max_length)
    {
        return FALSE;
    }

    for (int i = 0; i < sctx->needle_max_length; i++)
    {
        if (i >= sctx->needle_length)
        {
            break;
        }

        if (sctx->haystack[LIMIT_PATH_SIZE(i)] != sctx->needle[LIMIT_PATH_SIZE(i)])
        {
            return FALSE;
        }
    }

    return TRUE;
}


statfunc int ends_with(const struct string_utils_ctx *sctx)
{
    if (sctx->needle_length == 0 || sctx->needle_length > sctx->haystack_length || sctx->needle_length > sctx->needle_max_length)
    {
        return FALSE;
    }

    unsigned char start = sctx->haystack_length - sctx->needle_length;
    return is_needle_in_haystack_from_index(sctx, start);
}

statfunc unsigned char string_length(const char *str, unsigned char max_len)
{
    unsigned char len = 0;
    for (unsigned char i = 0; i < max_len; i++)
    {
        if (str[i] == '\0')
        {
            break;
        }
        len++;
    }
    return len;
}