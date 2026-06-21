#pragma once
#include "log_levels_enum.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "common_maps.bpf.h"

extern const volatile enum log_level log_level_to_print;
int report_error(int error_code, const char *location, const char *details);
statfunc struct printed_message* allocate_empty_printed_message(void);
struct printed_message;

enum bpf_func_id___x { BPF_FUNC_trace_vprintk___x = 177 };

#define bpf_has_trace_vprintk() bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_trace_vprintk___x)

#define bpf_log_printk(fmt, ...)                                                    \
do {                                                                                 \
    if (bpf_has_trace_vprintk())                                                     \
    {                                                                                \
        bpf_printk(fmt, ##__VA_ARGS__);                                              \
    }                                                                                \
    else                                                                             \
    {                                                                                \
        struct printed_message *message = allocate_empty_printed_message();          \
        if (message)                                                                 \
        {                                                                            \
            BPF_SNPRINTF(message->value, sizeof(message->value), fmt, ##__VA_ARGS__); \
            bpf_printk("%s", message->value);                                        \
        }                                                                            \
    }                                                                                \
} while (0)

#define REPORT_ERROR(CODE, FMT, ...)                                                \
do {                                                                                 \
    __u32 key = 0;                                                                   \
    struct error_report_t *t = bpf_map_lookup_elem(&temp_error_report_t, &key);      \
    if (t) {                                                                         \
        t->error_code = (CODE);                                                      \
        BPF_SNPRINTF(t->location, sizeof(t->location), "%s:%d", __func__, __LINE__); \
        BPF_SNPRINTF(t->details,  sizeof(t->details),  FMT, ##__VA_ARGS__);          \
        report_error(t->error_code, t->location, t->details);                        \
    }                                                                                \
} while (0)


#define LOG_DEBUG(FMT, ...)                                                          \
do {                                                                                 \
    if(log_level_to_print <= LOG_LEVEL_DEBUG)                                        \
    {                                                                                \
        unsigned int key = 0;                                                        \
        char *hook_name = bpf_map_lookup_elem(&hook_names, &key);                    \
        bpf_log_printk("[DEBUG][%s:%s:%d] " FMT, hook_name, __func__, __LINE__, ##__VA_ARGS__); \
    }                                                                                \
} while (0)


#define LOG_INFO(FMT, ...)                                                            \
do {                                                                                 \
    if(log_level_to_print <= LOG_LEVEL_INFO)                                         \
    {                                                                                \
        unsigned int key = 0;                                                        \
        char *hook_name = bpf_map_lookup_elem(&hook_names, &key);                    \
        bpf_log_printk("[INFO][%s:%s:%d] " FMT, hook_name, __func__, __LINE__, ##__VA_ARGS__); \
    }                                                                                \
} while (0)


statfunc void set_hook_name(const char * hook_name, char length)
{
    unsigned int key = 0;
    char *hook_name_p = bpf_map_lookup_elem(&hook_names, &key);
    if(!hook_name_p)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed. hook_name: %s", hook_name);
        return;
    }
    if(bpf_probe_read_kernel(hook_name_p, HOOK_NAME_MAX_LENGTH, &empty_hook_name) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed. hook_name: %s", hook_name);
        return;
    }
    if(bpf_probe_read_kernel(hook_name_p, length, hook_name) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed. hook_name: %s", hook_name);
    }
}
