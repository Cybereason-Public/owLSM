#pragma once
#include "common_maps.bpf.h"
#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"


statfunc struct printed_message* allocate_empty_printed_message(void)
{
    u32 key = 0;
    struct printed_message *message = bpf_map_lookup_elem(&printed_message_map, &key);
    if (!message)
    {
        bpf_printk("bpf_map_lookup_elem failed in allocate_empty_printed_message");
        return NULL;
    }
    if (bpf_probe_read_kernel(message, sizeof(*message), &empty_printed_message) != SUCCESS)
    {
        bpf_printk("bpf_probe_read_kernel failed in allocate_empty_printed_message");
        return NULL;
    }
    return message;
}

statfunc struct string_buffer* allocate_string_buffer(void)
{
    u32 key = 0;
    u32 *idx = bpf_map_lookup_elem(&heap_string_buffer_map_counter, &key);
    if (!idx)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return NULL;
    }

    if(*idx >= HEAP_SLOTS)
    {
        *idx = 0;
    }
    unsigned int slot = *idx;
    (*idx)++;

    struct string_buffer *s = bpf_map_lookup_elem(&heap_string_buffer_map, &slot);
    if (!s) 
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return NULL;
    }
    if(bpf_probe_read_kernel(s, sizeof(*s), &empty_string_buffer) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel faield");
        return NULL;
    }

    return s;
}

statfunc struct process_t* allocate_process_t(void)
{
    u32 key = 0;
    u32 *idx = bpf_map_lookup_elem(&heap_process_t_map_counter, &key);
    if (!idx)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return NULL;
    }
    
    if(*idx >= HEAP_SLOTS)
    {
        *idx = 0;
    }
    unsigned int slot = *idx;
    (*idx)++;

    struct process_t *p = bpf_map_lookup_elem(&heap_process_t_map, &slot);
    if (!p) 
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return NULL;
    }
    if(bpf_probe_read_kernel(p, sizeof(*p), &empty_process_t) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }

    return p;
}

statfunc struct event_t* allocate_empty_event()
{
    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
    if(!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_ringbuf_reserve failed");
        return NULL;
    }
    if(bpf_probe_read_kernel(event, sizeof(*event), &empty_event_t) != SUCCESS)
    {
        bpf_ringbuf_discard(event, 0);
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }
    return event;
}

statfunc unsigned long long get_next_event_id()
{
    return __sync_fetch_and_add(&global_event_id_counter, 1);
}

statfunc struct event_t* allocate_event_with_basic_stats()
{
    struct event_t *event = allocate_empty_event();
    if(event)
    {
        event->time = bpf_ktime_get_ns();
        event->id = get_next_event_id();
        if(event->id == 0)
        {
            bpf_ringbuf_discard(event, 0);
            return NULL;
        }
    }

    return event;
}

statfunc struct string_utils_ctx* allocate_empty_string_utils_ctx()
{
    int key = 0;
    struct string_utils_ctx *sctx = bpf_map_lookup_elem(&heap_string_utils_ctx, &key);
    if (!sctx)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return NULL;
    }
    if(bpf_probe_read_kernel(sctx, sizeof(*sctx), &string_utils_ctx_empty) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return NULL;
    }
    return sctx;
}