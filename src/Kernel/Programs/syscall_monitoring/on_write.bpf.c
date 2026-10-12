#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "preprocessor_definitions/fs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "k8s_ignored_events.bpf.h"

#define WRITE_EVENT
#include "event_caching.bpf.h"
#include "tail_calls_manager.bpf.h"

SEC("lsm/file_permission")
int BPF_PROG(write_hook, struct file *file, int mask) 
{
    set_hook_name("write_hook", 10);
    if(!is_userspace_program())
    {
        return ALLOW;
    }

    if (!(mask & (MAY_WRITE | MAY_APPEND))) 
    {
        return ALLOW;
    }

    unsigned long long mode = BPF_CORE_READ(file, f_inode, i_mode);
    if(!S_ISLNK(mode) && !S_ISREG(mode))
    {
        return ALLOW;
    }

    if(is_current_pid_related())
    {
        return ALLOW;
    }

    if(k8s_ignore_current_process())
    {
        return ALLOW;
    }

    unsigned long long event_hash = calculate_event_hash(file);
    int verdict = get_write_event_verdict_from_cache(&event_hash);
    if(verdict != NOT_IN_CACHE)
    {
        return verdict == ALLOW ? ALLOW : DENY;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed");
        return ALLOW;
    }

    event->type = WRITE;
    if(fill_write_event_t(&event->data.write, file, &event_hash) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_write_event_t failed");
        goto allow_event;
    }

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);

    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &write_prog_array);
    return ALLOW;
    
allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/file_permission")
int BPF_PROG(write_hook_2, struct file *file, int mask) 
{
    set_hook_name("write_hook_2", 12);
    int verdict = generic_tail_call(); 
    struct event_t* current_event = get_currently_handled_event();
    if(current_event)
    {
        update_write_event_verdict_to_cache(&current_event->data.write.event_hash, verdict);
    }
    return verdict == ALLOW ? ALLOW : DENY;
}

char LICENSE[] SEC("license") = "GPL";