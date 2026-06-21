#define DEFINE_MAPS
#include "common_maps.bpf.h" 

const struct string_buffer   empty_string_buffer     SEC(".rodata") = { };
const struct process_t       empty_process_t         SEC(".rodata") = { };
const struct event_t         empty_event_t           SEC(".rodata") = { };
const struct error_report_t empty_error_report_t     SEC(".rodata") = { };
const char empty_hook_name[HOOK_NAME_MAX_LENGTH]     SEC(".rodata") = { };
const struct string_utils_ctx string_utils_ctx_empty SEC(".rodata") = { };
const struct command_line_t   empty_command_line_t   SEC(".rodata") = { };
const struct printed_message  empty_printed_message  SEC(".rodata") = { };
const volatile struct ebpf_features g_ebpf_features SEC(".rodata");
volatile unsigned long long global_event_id_counter = 1;