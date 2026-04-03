#pragma once
#include "rodata_maps_related_structs.h"
#include "rules_structs.h"

#ifndef HEAP_SLOTS
#define HEAP_SLOTS 8
#endif

#ifndef MAX_SHELL_INSTANCES
#define MAX_SHELL_INSTANCES 16
#endif

#ifndef PID_MAX_LIMIT
#define PID_MAX_LIMIT 4096
#endif

extern const struct string_buffer    empty_string_buffer                   SEC(".rodata");
extern const struct process_t        empty_process_t                       SEC(".rodata");
extern const struct event_t          empty_event_t                         SEC(".rodata");
extern const struct error_report_t   empty_error_report_t                  SEC(".rodata");
extern const struct string_utils_ctx string_utils_ctx_empty                SEC(".rodata");
extern const char                    empty_hook_name[HOOK_NAME_MAX_LENGTH] SEC(".rodata");
extern const struct command_line_t   empty_command_line_t                  SEC(".rodata");

#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
} rb SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 21);
} errors SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type,       BPF_MAP_TYPE_HASH);
        __uint(max_entries, PID_MAX_LIMIT);
        __type(key,        u32);
        __type(value,      struct process_t);
} alive_process_cache_map SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type,       BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, PID_MAX_LIMIT);
        __type(key,        unsigned long long);
        __type(value,      struct process_t);
} dead_process_cache_lru_map SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct string_buffer);
        __uint(max_entries, HEAP_SLOTS);
} heap_string_buffer_map SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct process_t);
    __uint(max_entries, HEAP_SLOTS);
} heap_process_t_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} heap_string_buffer_map_counter SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} heap_process_t_map_counter SEC(".maps");
    

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} currently_handled_event SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } tail_call_counter SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct error_report_t);
} temp_error_report_t SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32);
    __type(value, unsigned long long);
} ebpf_program_start_time SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, int);
} parent_processes_to_kill SEC(".maps");


#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type,       BPF_MAP_TYPE_HASH);
        __uint(max_entries, PID_MAX_LIMIT);
        __type(key,        u32);
        __type(value,      int);
} program_related_pids SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
volatile unsigned long long global_event_id_counter;

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[HOOK_NAME_MAX_LENGTH]);
} hook_names SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct string_utils_ctx);
} heap_string_utils_ctx SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      struct predicate_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} predicates_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      struct rule_string_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} rules_strings_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      struct rule_ip_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} rules_ips_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      struct predicate_result_t);
} predicates_results_cache SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      struct flat_2d_dfa_array_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} idx_to_DFA_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOTAL_PREDS);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,        u32);
    __type(value,      unsigned long long);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} idx_to_accepting_states_map SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type,       BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
    __type(key,        u32);
    __type(value,      struct rule_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} network_rules SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SHELL_INSTANCES);
    __type(key, unsigned int);
    __type(value, unsigned char);
} active_shell_pids SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
        __uint(type,       BPF_MAP_TYPE_HASH);
        __uint(max_entries, PID_MAX_LIMIT);
        __uint(map_flags,   BPF_F_NO_PREALLOC);
        __type(key,        u32);
        __type(value,      unsigned char);
} kthread_exec_pids SEC(".maps");

#ifndef DEFINE_MAPS
extern
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct eval_stack);
} helper_stack SEC(".maps");