#pragma once
#include "preprocessor_definitions/defs.bpf.h"
#include "error_reports.bpf.h"
#include "event_and_rule_matcher.bpf.h"
#include "prevention.bpf.h"

#define MAX_TAIL_CALL_CNT 32

statfunc int get_current_and_increment_tail_counter()
{
    u32 idx = 0;
    u32 *p = bpf_map_lookup_elem(&tail_call_counter, &idx);
    if(!p)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return GENERIC_ERROR;
    }

    int v = *p;
    ++(*p);
    bpf_map_update_elem(&tail_call_counter, &idx, p, BPF_ANY);
    return v;
}

statfunc void reset_tail_counter()
{
    u32 idx = 0;
    bpf_map_update_elem(&tail_call_counter, &idx, &idx, BPF_ANY);
}

#ifdef CHMOD_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } chmod_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } chmod_rules SEC(".maps");
#endif // CHMOD_EVENT

#ifdef CHOWN_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } chown_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } chown_rules SEC(".maps");
#endif // CHOWN_EVENT

#ifdef EXEC_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } exec_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } exec_rules SEC(".maps");
#endif // EXEC_EVENT

#ifdef FILE_CREATE_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } fc_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } file_create_rules SEC(".maps");
#endif // FILE_CREATE_EVENT

#ifdef RMDIR_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } rmdir_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } rmdir_rules SEC(".maps");
#endif // RMDIR_EVENT

#ifdef MKDIR_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } mkdir_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } mkdir_rules SEC(".maps");
#endif // MKDIR_EVENT

#ifdef WRITE_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } write_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } write_rules SEC(".maps");
#endif // WRITE_EVENT

#ifdef READ_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } read_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
      } read_rules SEC(".maps");
#endif // READ_EVENT

#ifdef UNLINK_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } unlink_prog_array SEC(".maps");

    struct {
        __uint(type,       BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
        __type(key,        u32);
        __type(value,      struct rule_t);
        __uint(pinning,    LIBBPF_PIN_BY_NAME);
    } unlink_rules SEC(".maps");
#endif // UNLINK_EVENT

#ifdef RENAME_EVENT
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, u32);
} rename_prog_array SEC(".maps");

struct {
    __uint(type,       BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES_PER_MAP_PLUS1);
    __type(key,        u32);
    __type(value,      struct rule_t);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
} rename_rules SEC(".maps");
#endif // RENAME_EVENT

#ifdef CONNECT_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } connect_prog_array SEC(".maps");
#endif // CONNECT_EVENT

#ifdef ACCEPT_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } accept_prog_array SEC(".maps");

    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } inet_conn_request_prog_array SEC(".maps");
#endif // ACCEPT_EVENT

#ifdef DASH_SHELL_COMMAND_EVENT
    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key,   u32);
        __type(value, u32);
    } dash_shell_command_prog_array SEC(".maps");

#endif // DASH_SHELL_COMMAND_EVENT

statfunc void do_tail_call(void* ctx, void* prog_array)
{
    int hops = get_current_and_increment_tail_counter();
    if(hops == GENERIC_ERROR)
    {
        return;
    }

    if(hops < MAX_TAIL_CALL_CNT)
    {
        bpf_tail_call(ctx, prog_array, 0);
        REPORT_ERROR(GENERIC_ERROR, "bpf_tail_call failed. hops: %d", hops);
    }
}

statfunc int store_currently_handled_event(struct event_t* e)
{
    u32 key = 0;

    if (g_ebpf_features.ringbuffer_map_value_available)
    {
        if (bpf_map_update_elem(&currently_handled_event, &key, e, BPF_ANY) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed");
            return GENERIC_ERROR;
        }
    }
    else
    {
        struct event_t *slot = bpf_map_lookup_elem(&currently_handled_event, &key);
        if (!slot)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
            return GENERIC_ERROR;
        }

        if (bpf_probe_read_kernel(slot, sizeof(*slot), e) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
            return GENERIC_ERROR;
        }
    }

    return SUCCESS;
}

statfunc void submit_event_to_userspace(struct event_t* event)
{
    struct event_t *event_to_send = allocate_empty_event();
    if(!event_to_send)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_ringbuf_reserve failed");
    }
    else 
    {
        if(bpf_probe_read_kernel(event_to_send, sizeof(*event_to_send), event) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed. event.id: %u", event->id);
            bpf_ringbuf_discard(event_to_send, 0);
        }
        else
        {
            bpf_ringbuf_submit(event_to_send, 0);
        }
    }
}

statfunc void submit_event(struct event_t* event)
{
    if(event->action != EXCLUDE_EVENT)
    {
        submit_event_to_userspace(event);
    }
}

statfunc int generic_tail_call()
{
    struct event_t* current_event = get_currently_handled_event();
    if(!current_event)
    {
        REPORT_ERROR(GENERIC_ERROR, "get_currently_handled_event failed");
        goto allow_event;
    }

#ifdef CHMOD_EVENT
    bpf_for_each_map_elem(&chmod_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined CHOWN_EVENT
    bpf_for_each_map_elem(&chown_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined EXEC_EVENT
    bpf_for_each_map_elem(&exec_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined FILE_CREATE_EVENT
    bpf_for_each_map_elem(&file_create_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined MKDIR_EVENT
    bpf_for_each_map_elem(&mkdir_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined RMDIR_EVENT
    bpf_for_each_map_elem(&rmdir_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined WRITE_EVENT
    bpf_for_each_map_elem(&write_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined READ_EVENT
    bpf_for_each_map_elem(&read_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined UNLINK_EVENT
    bpf_for_each_map_elem(&unlink_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined RENAME_EVENT
    bpf_for_each_map_elem(&rename_rules, event_rule_matcher_callback, &current_event, 0);
#elif defined NETWORK_EVENT
    bpf_for_each_map_elem(&network_rules, event_rule_matcher_callback, &current_event, 0);
#endif
    
    if(current_event->id > 0)
    {
        submit_event(current_event);
    }

    if(current_event->action == KILL_PROCESS || current_event->action == BLOCK_KILL_PROCESS || current_event->action == BLOCK_KILL_PROCESS_KILL_PARENT)
    {
        kill_proccesses(current_event->action, current_event);
    }

    if(current_event->action == BLOCK_EVENT || current_event->action == BLOCK_KILL_PROCESS || current_event->action == BLOCK_KILL_PROCESS_KILL_PARENT)
    {
        return DENY;
    }

allow_event:
    return ALLOW;   
}

statfunc void discard_sk_from_sk_storage(struct sock *sk, void* sk_storage)
{
    if (!sk) 
    {
        REPORT_ERROR(GENERIC_ERROR, "sk is null");
    }
    else if(bpf_sk_storage_delete(sk_storage, sk) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_sk_storage_delete failed, sk: %p", sk);
    }
}

statfunc void set_event_id_when_id_is_zero(struct event_t *event)
{
    if(event->id != 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "event->id is not 0");
    }
    else 
    {
        event->id = get_next_event_id();
    }
}

statfunc int network_event_tcp_outgoing_tail_call(struct sock *sk, void* sk_storage)
{
    int ret = ALLOW;
    struct event_t *event = get_currently_handled_event();
    if(!event)
    {   
        REPORT_ERROR(GENERIC_ERROR, "get_currently_handled_event failed");
        goto discard_sk_storage;
    }
    
    event->time = bpf_ktime_get_ns();
    ret = generic_tail_call();
    if(ret == ALLOW)
    {
        return ALLOW;  // inet_conn_established needs to add the local ip and port.
    }
    else
    {
        set_event_id_when_id_is_zero(event);
        submit_event(event);
    }

discard_sk_storage:
    discard_sk_from_sk_storage(sk, sk_storage);
    return ret;
}

statfunc int network_event_tcp_incoming_tail_call(struct sock *sk, void* sk_storage)
{
    int ret = ALLOW;
    struct event_t *event = get_currently_handled_event();
    if(!event)
    {   
        REPORT_ERROR(GENERIC_ERROR, "get_currently_handled_event failed");
        goto discard_sk_storage;
    }

    set_event_id_when_id_is_zero(event);
    event->time = bpf_ktime_get_ns();
    ret = generic_tail_call();

discard_sk_storage:
    discard_sk_from_sk_storage(sk, sk_storage);
    return ret;
}