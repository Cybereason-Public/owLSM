#pragma once
#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "rules_structs.h"
#include "string_utils.bpf.h"
#include "event_and_rule_matcher_fieldref_helper.bpf.h"

int eval_file(const struct event_t *current_event, const struct file_t *file, struct predicate_t *pred, enum rule_field_type rule_file_field_type);

int eval_process(const struct event_t *current_event, const struct process_t *process, struct predicate_t *pred, enum rule_field_type rule_file_field_type);

int evaluate_token_against_event(struct token_t *token, struct eval_stack *stack, const struct event_t *event);

#define STACK_IDX(stack_pointer) ({                                    \
    unsigned char __idx = (stack_pointer) & (MAX_TOKENS_PER_RULE - 1); \
    asm volatile("" : "+r"(__idx));                                    \
    __idx;                                                             \
})

statfunc struct eval_stack* get_helper_stack(void)
{
    unsigned int key = 0;
    return bpf_map_lookup_elem(&helper_stack, &key);
}

statfunc int stack_empty(struct eval_stack *stack)
{
    return (!stack || stack->stack_pointer == 0);
}

statfunc int stack_push(struct eval_stack *stack, struct token_t *token)
{
    if (!stack || !token || stack->stack_pointer >= MAX_TOKENS_PER_RULE)
        return FALSE;

    stack->tokens[STACK_IDX(stack->stack_pointer)] = *token;
    stack->stack_pointer++;
    return TRUE;
}

statfunc int stack_pop(struct eval_stack *stack, struct token_t *out)
{
    if (stack_empty(stack) || !out)
        return FALSE;

    stack->stack_pointer--;
    *out = stack->tokens[STACK_IDX(stack->stack_pointer)];
    return TRUE;
}

statfunc int stack_top(struct eval_stack *stack, struct token_t *out)
{
    if (stack_empty(stack) || !out)
        return FALSE;

    *out = stack->tokens[STACK_IDX(stack->stack_pointer - 1)];
    return TRUE;
}

statfunc enum token_result get_cached_pred_result(unsigned int pred_idx, const struct event_t *event)
{
    if(event->time == 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "event->time is 0");
        return TOKEN_RESULT_UNKNOWN;
    }

    struct predicate_result_t *result = bpf_map_lookup_elem(&predicates_results_cache, &pred_idx);
    if(!result)
    {
        return TOKEN_RESULT_UNKNOWN;
    }

    if(event->time == result->time)
    {
        return result->result;
    }
    return TOKEN_RESULT_UNKNOWN;
}

statfunc void set_cached_pred_result(unsigned int pred_idx, enum token_result pred_result, const struct event_t *event)
{
    if(event->time == 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "event->time is 0");
        return;
    }

    struct predicate_result_t result = {
        .time = event->time,
        .result = pred_result
    };
    if(bpf_map_update_elem(&predicates_results_cache, &pred_idx, &result, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed");
    }
}

statfunc int compare_numeric(const struct event_t *current_event, int event_value, struct predicate_t *pred)
{
    int rule_value = 0;
    if(pred->fieldref != FIELD_TYPE_NONE)
    {
        rule_value = fieldref_pred_get_numeric_value(current_event, pred->fieldref);
    }
    else
    {
        rule_value = pred->numerical_value;
    }

    switch (pred->operation)
    {
        case COMPARISON_TYPE_EQUAL:       return event_value == rule_value;
        case COMPARISON_TYPE_ABOVE:       return event_value > rule_value;
        case COMPARISON_TYPE_BELOW:       return event_value < rule_value;
        case COMPARISON_TYPE_EQUAL_ABOVE: return event_value >= rule_value;
        case COMPARISON_TYPE_EQUAL_BELOW: return event_value <= rule_value;
        default:
            REPORT_ERROR(GENERIC_ERROR, "invalid numeric operation: %d", pred->operation);
            return FALSE;
    }
}

statfunc struct string_utils_ctx * create_sctx(const char *haystack, unsigned char haystack_length, unsigned char haystack_max_length, struct predicate_t *pred)
{
    struct rule_string_t *str = bpf_map_lookup_elem(&rules_strings_map, &pred->string_idx);
    if (!str)
    {
        REPORT_ERROR(GENERIC_ERROR, "string lookup failed for idx %d", pred->string_idx);
        return NULL;
    }

    struct string_utils_ctx *sctx = string_utils_setup(haystack, str->value, haystack_length, str->length, haystack_max_length);
    if (!sctx)
    {
        REPORT_ERROR(GENERIC_ERROR, "string_utils_ctx is null");
        return NULL;
    }
    
    sctx->idx_to_DFA = str->idx_to_DFA;
    sctx->comparison_type = pred->operation;
    return sctx;
}

statfunc struct string_utils_ctx *create_sctx_fieldref(const char *haystack, unsigned char haystack_length, unsigned char haystack_max_length, struct predicate_t *pred)
{
    struct string_utils_ctx *sctx = allocate_empty_string_utils_ctx();
    if (!sctx)
    {
        return NULL;
    }
    
    barrier_var(haystack_max_length);
    if(bpf_probe_read_kernel(sctx->haystack, haystack_max_length, haystack) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }
    if(fieldref_pred_fill_needle(sctx, pred->fieldref) != TRUE)
    {
        REPORT_ERROR(GENERIC_ERROR, "fieldref_pred_fill_needle failed");
        return NULL;
    }

    sctx->haystack_max_length = haystack_max_length;
    sctx->haystack_length = haystack_length;
    sctx->comparison_type = pred->operation;

    return sctx;
}

statfunc int compare_string(const char *haystack, unsigned char haystack_length, unsigned char haystack_max_length, struct predicate_t *pred)
{
    struct string_utils_ctx *sctx = NULL;
    if(pred->fieldref != FIELD_TYPE_NONE)
    {
        sctx = create_sctx_fieldref(haystack, haystack_length, haystack_max_length, pred);
    }
    else
    {
        sctx = create_sctx(haystack, haystack_length, haystack_max_length, pred);
    }

    if(!sctx)
    {
        return FALSE;
    }

    switch (sctx->comparison_type) 
    {
        case COMPARISON_TYPE_EXACT_MATCH: return string_exact_match(sctx);
        case COMPARISON_TYPE_CONTAINS: return string_contains(sctx);
        case COMPARISON_TYPE_STARTS_WITH: return starts_with(sctx);
        case COMPARISON_TYPE_ENDS_WITH: return ends_with(sctx);
        case COMPARISON_TYPE_REGEX: return regex_dfa_search(sctx);
        default:
            REPORT_ERROR(GENERIC_ERROR, "compare_string unknown comparison type: %d", sctx->comparison_type);
            return FALSE;
    }
    return FALSE;
}

statfunc int eval_ip(const struct network_event_t *event, struct predicate_t *pred)
{
    struct rule_ip_t *ip = bpf_map_lookup_elem(&rules_ips_map, &pred->numerical_value);
    if(!ip)
    {
        REPORT_ERROR(GENERIC_ERROR, "ip lookup failed for idx %d", pred->numerical_value);
        return FALSE;
    }

    if(event->ip_type == AF_INET)
    {
        if(pred->field == NETWORK_SOURCE_IP)
        {
            return ((event->addresses.ipv4.source_ip & ip->cidr_mask[0]) == (ip->ip[0] & ip->cidr_mask[0]));
        }
        else if(pred->field == NETWORK_DESTINATION_IP)
        {
            return ((event->addresses.ipv4.destination_ip & ip->cidr_mask[0]) == (ip->ip[0] & ip->cidr_mask[0]));
        }
        else
        {
            REPORT_ERROR(GENERIC_ERROR, "eval_ip unknown field: %d", pred->field);
            return FALSE;
        }
    }
    else if(event->ip_type == AF_INET6)
    {
        if(pred->field == NETWORK_SOURCE_IP)
        {
            return ((event->addresses.ipv6.source_ip[0] & ip->cidr_mask[0]) == (ip->ip[0] & ip->cidr_mask[0])) &&
                   ((event->addresses.ipv6.source_ip[1] & ip->cidr_mask[1]) == (ip->ip[1] & ip->cidr_mask[1])) &&
                   ((event->addresses.ipv6.source_ip[2] & ip->cidr_mask[2]) == (ip->ip[2] & ip->cidr_mask[2])) &&
                   ((event->addresses.ipv6.source_ip[3] & ip->cidr_mask[3]) == (ip->ip[3] & ip->cidr_mask[3]));
        }
        else if(pred->field == NETWORK_DESTINATION_IP)
        {
            return ((event->addresses.ipv6.destination_ip[0] & ip->cidr_mask[0]) == (ip->ip[0] & ip->cidr_mask[0])) &&
                   ((event->addresses.ipv6.destination_ip[1] & ip->cidr_mask[1]) == (ip->ip[1] & ip->cidr_mask[1])) &&
                   ((event->addresses.ipv6.destination_ip[2] & ip->cidr_mask[2]) == (ip->ip[2] & ip->cidr_mask[2])) &&
                   ((event->addresses.ipv6.destination_ip[3] & ip->cidr_mask[3]) == (ip->ip[3] & ip->cidr_mask[3]));
        }
        else
        {
            REPORT_ERROR(GENERIC_ERROR, "eval_ip unknown field: %d", pred->field);
            return FALSE;
        }
    }
    else 
    {
        REPORT_ERROR(GENERIC_ERROR, "eval_ip unknown ip type: %d", event->ip_type);
        return FALSE;
    }
}

statfunc int eval_target_file(const struct event_t *current_event, struct predicate_t *pred)
{
    switch (current_event->type)
    {
        case FILE_CREATE: return eval_file(current_event, &current_event->data.file_create.file, pred, pred->field);
        case MKDIR: return eval_file(current_event, &current_event->data.mkdir.file, pred, pred->field);
        case RMDIR: return eval_file(current_event, &current_event->data.rmdir.file, pred, pred->field);
        case CHOWN: return eval_file(current_event, &current_event->data.chown.file, pred, pred->field);
        case CHMOD: return eval_file(current_event, &current_event->data.chmod.file, pred, pred->field);
        case READ: return eval_file(current_event, &current_event->data.read.file, pred, pred->field);
        case WRITE: return eval_file(current_event, &current_event->data.write.file, pred, pred->field);
        case UNLINK: return eval_file(current_event, &current_event->data.unlink.file, pred, pred->field);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return FALSE;
    }
}

statfunc int eval_target_process(const struct event_t *current_event, struct predicate_t *pred, enum rule_field_type rule_file_field_type)
{
    switch (current_event->type)
    {
        case EXEC: return eval_process(current_event, &current_event->data.exec.new_process, pred, rule_file_field_type);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return FALSE;
    }
}

statfunc int eval_pred(unsigned int pred_idx, const struct event_t *current_event)
{
    struct predicate_t *pred = bpf_map_lookup_elem(&predicates_map, &pred_idx);
    if(!pred)
    {
        REPORT_ERROR(GENERIC_ERROR, "pred lookup failed for idx %d", pred_idx);
        return FALSE;
    }

    switch (pred->field)
    {
        case TARGET_FILE_PATH: return eval_target_file(current_event, pred);
        case TARGET_FILE_FILENAME: return eval_target_file(current_event, pred);
        case TARGET_FILE_OWNER_UID: return eval_target_file(current_event, pred);
        case TARGET_FILE_OWNER_GID: return eval_target_file(current_event, pred);
        case TARGET_FILE_MODE: return eval_target_file(current_event, pred);
        case TARGET_FILE_SUID: return eval_target_file(current_event, pred);
        case TARGET_FILE_SGID: return eval_target_file(current_event, pred);
        case TARGET_FILE_NLINK: return eval_target_file(current_event, pred);
        case TARGET_FILE_TYPE: return eval_target_file(current_event, pred);
        case TARGET_PROCESS_PID: return eval_target_process(current_event, pred, TARGET_PROCESS_PID);
        case TARGET_PROCESS_PPID: return eval_target_process(current_event, pred, TARGET_PROCESS_PPID);
        case TARGET_PROCESS_RUID: return eval_target_process(current_event, pred, TARGET_PROCESS_RUID);
        case TARGET_PROCESS_RGID: return eval_target_process(current_event, pred, TARGET_PROCESS_RGID);
        case TARGET_PROCESS_EUID: return eval_target_process(current_event, pred, TARGET_PROCESS_EUID);
        case TARGET_PROCESS_EGID: return eval_target_process(current_event, pred, TARGET_PROCESS_EGID);
        case TARGET_PROCESS_SUID: return eval_target_process(current_event, pred, TARGET_PROCESS_SUID);
        case TARGET_PROCESS_PTRACE_FLAGS: return eval_target_process(current_event, pred, TARGET_PROCESS_PTRACE_FLAGS);
        case TARGET_PROCESS_CMD: return eval_target_process(current_event, pred, TARGET_PROCESS_CMD);
        case TARGET_PROCESS_SHELL_COMMAND: return eval_target_process(current_event, pred, TARGET_PROCESS_SHELL_COMMAND);
        case TARGET_PROCESS_FILE_PATH: return eval_target_process(current_event, pred, TARGET_FILE_PATH);
        case TARGET_PROCESS_FILE_FILENAME: return eval_target_process(current_event, pred, TARGET_FILE_FILENAME);
        case TARGET_PROCESS_FILE_OWNER_UID: return eval_target_process(current_event, pred, TARGET_FILE_OWNER_UID);
        case TARGET_PROCESS_FILE_OWNER_GID: return eval_target_process(current_event, pred, TARGET_FILE_OWNER_GID);
        case TARGET_PROCESS_FILE_MODE: return eval_target_process(current_event, pred, TARGET_FILE_MODE);
        case TARGET_PROCESS_FILE_SUID: return eval_target_process(current_event, pred, TARGET_FILE_SUID);
        case TARGET_PROCESS_FILE_SGID: return eval_target_process(current_event, pred, TARGET_FILE_SGID);
        case TARGET_PROCESS_FILE_NLINK: return eval_target_process(current_event, pred, TARGET_FILE_NLINK);
        case TARGET_PROCESS_FILE_TYPE: return eval_target_process(current_event, pred, TARGET_FILE_TYPE);
        case PROCESS_PID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_PID);
        case PROCESS_PPID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_PPID);
        case PROCESS_RUID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_RUID);
        case PROCESS_RGID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_RGID);
        case PROCESS_EUID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_EUID);
        case PROCESS_EGID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_EGID);
        case PROCESS_SUID: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_SUID);
        case PROCESS_PTRACE_FLAGS: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_PTRACE_FLAGS);
        case PROCESS_CMD: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_CMD);
        case PROCESS_SHELL_COMMAND: return eval_process(current_event, &current_event->process, pred, TARGET_PROCESS_SHELL_COMMAND);
        case PROCESS_FILE_PATH: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_PATH);
        case PROCESS_FILE_FILENAME: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_FILENAME);
        case PROCESS_FILE_OWNER_UID: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_OWNER_UID);
        case PROCESS_FILE_OWNER_GID: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_OWNER_GID);
        case PROCESS_FILE_MODE: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_MODE);
        case PROCESS_FILE_SUID: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_SUID);
        case PROCESS_FILE_SGID: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_SGID);
        case PROCESS_FILE_NLINK: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_NLINK);
        case PROCESS_FILE_TYPE: return eval_process(current_event, &current_event->process, pred, TARGET_FILE_TYPE);
        case PARENT_PROCESS_PID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_PID);
        case PARENT_PROCESS_PPID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_PPID);
        case PARENT_PROCESS_RUID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_RUID);
        case PARENT_PROCESS_RGID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_RGID);
        case PARENT_PROCESS_EUID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_EUID);
        case PARENT_PROCESS_EGID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_EGID);
        case PARENT_PROCESS_SUID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_SUID);
        case PARENT_PROCESS_PTRACE_FLAGS: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_PTRACE_FLAGS);
        case PARENT_PROCESS_CMD: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_CMD);
        case PARENT_PROCESS_SHELL_COMMAND: return eval_process(current_event, &current_event->parent_process, pred, TARGET_PROCESS_SHELL_COMMAND);
        case PARENT_PROCESS_FILE_PATH: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_PATH);
        case PARENT_PROCESS_FILE_FILENAME: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_FILENAME);
        case PARENT_PROCESS_FILE_OWNER_UID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_OWNER_UID);
        case PARENT_PROCESS_FILE_OWNER_GID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_OWNER_GID);
        case PARENT_PROCESS_FILE_MODE: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_MODE);
        case PARENT_PROCESS_FILE_SUID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_SUID);
        case PARENT_PROCESS_FILE_SGID: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_SGID);
        case PARENT_PROCESS_FILE_NLINK: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_NLINK);
        case PARENT_PROCESS_FILE_TYPE: return eval_process(current_event, &current_event->parent_process, pred, TARGET_FILE_TYPE);
        case RENAME_SOURCE_FILE_PATH: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_PATH);
        case RENAME_SOURCE_FILE_FILENAME: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_FILENAME);
        case RENAME_SOURCE_FILE_OWNER_UID: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_OWNER_UID);
        case RENAME_SOURCE_FILE_OWNER_GID: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_OWNER_GID);
        case RENAME_SOURCE_FILE_MODE: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_MODE);
        case RENAME_SOURCE_FILE_SUID: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_SUID);
        case RENAME_SOURCE_FILE_SGID: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_SGID);
        case RENAME_SOURCE_FILE_NLINK: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_NLINK);
        case RENAME_SOURCE_FILE_TYPE: return eval_file(current_event, &current_event->data.rename.source_file, pred, TARGET_FILE_TYPE);
        case RENAME_DESTINATION_FILE_PATH: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_PATH);
        case RENAME_DESTINATION_FILE_FILENAME: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_FILENAME);
        case RENAME_DESTINATION_FILE_OWNER_UID: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_OWNER_UID);
        case RENAME_DESTINATION_FILE_OWNER_GID: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_OWNER_GID);
        case RENAME_DESTINATION_FILE_MODE: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_MODE);
        case RENAME_DESTINATION_FILE_SUID: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_SUID);
        case RENAME_DESTINATION_FILE_SGID: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_SGID);
        case RENAME_DESTINATION_FILE_NLINK: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_NLINK);
        case RENAME_DESTINATION_FILE_TYPE: return eval_file(current_event, &current_event->data.rename.destination_file, pred, TARGET_FILE_TYPE);
        case CHMOD_REQUESTED_MODE: return compare_numeric(current_event, current_event->data.chmod.requested_mode, pred);
        case NETWORK_SOURCE_IP: return eval_ip(&current_event->data.network, pred);
        case NETWORK_DESTINATION_IP: return eval_ip(&current_event->data.network, pred);
        case NETWORK_SOURCE_PORT: return compare_numeric(current_event, current_event->data.network.source_port, pred);
        case NETWORK_DESTINATION_PORT: return compare_numeric(current_event, current_event->data.network.destination_port, pred);
        case NETWORK_DIRECTION: return compare_numeric(current_event, current_event->data.network.direction, pred);
        default:
            REPORT_ERROR(GENERIC_ERROR, "invalid field: %d", pred->field);
            return FALSE;
    }

    return FALSE;
}

statfunc enum token_result get_pred_evaluation(struct token_t *token, const struct event_t *current_event)
{
    if(token->result != TOKEN_RESULT_UNKNOWN)
    {
        return token->result;
    }

    enum token_result cached_result = get_cached_pred_result(token->pred_idx, current_event);
    if(cached_result != TOKEN_RESULT_UNKNOWN)
    {
        return cached_result;
    }
    
    int eval_result = eval_pred(token->pred_idx, current_event);
    token->result = eval_result == TRUE ? TOKEN_RESULT_TRUE : TOKEN_RESULT_FALSE;
    set_cached_pred_result(token->pred_idx, token->result, current_event);
    return token->result;
}

statfunc int evaluate_rule_against_event(struct rule_t *rule, const struct event_t *event)
{
    if(!rule || !event)
    {
        return FALSE;
    }
    
    struct eval_stack *stack = get_helper_stack();
    if (!stack)
    {
        REPORT_ERROR(GENERIC_ERROR, "helper_stack lookup failed");
        return FALSE;
    }

    stack->stack_pointer = 0;
    for (int i = 0; i < MAX_TOKENS_PER_RULE; i++)
    {
        if (i >= rule->token_count)
        {
            break;
        }

        struct token_t *token = &rule->tokens[i];
        if(!evaluate_token_against_event(token, stack, event))
        {
            return FALSE;
        }
    }

    if (stack->stack_pointer != 1)
    {
        REPORT_ERROR(GENERIC_ERROR, "invalid final stack state: stack_pointer=%d", stack->stack_pointer);
        return FALSE;
    }

    struct token_t final_token;
    if (!stack_pop(stack, &final_token))
    {
        REPORT_ERROR(GENERIC_ERROR, "final pop failed");
        return FALSE;
    }

    enum token_result final_result = get_pred_evaluation(&final_token, event);
    return (final_result == TOKEN_RESULT_TRUE) ? TRUE : FALSE;
}

static long event_rule_matcher_callback(struct bpf_map *map, const void *key, void *value, void *callback_ctx)
{
    struct event_t** current_event_p = (struct event_t**)callback_ctx;
    if(!current_event_p)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_event_p is null");
        return 1; 
    }

    struct rule_t* current_rule = (struct rule_t*)value;
    if(!current_rule)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_rule is null");
        return 1;
    }

    struct event_t* current_event = *current_event_p;
    if(!current_event)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_event is null");
        return 1;
    }

    if (current_rule->is_end_of_rules)
    {
        return 1;
    }

    if(evaluate_rule_against_event(current_rule, current_event) == TRUE)
    {
        current_event->action = current_rule->action;
        current_event->matched_rule_id = current_rule->id;
        return 1;
    }

    return 0;
}