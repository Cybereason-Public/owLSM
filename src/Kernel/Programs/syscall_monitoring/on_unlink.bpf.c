#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "k8s_ignored_events.bpf.h"

#define UNLINK_EVENT
#include "tail_calls_manager.bpf.h"


SEC("lsm/path_unlink")
int BPF_PROG(unlink_hook, const struct path *dir, struct dentry *dentry)
{
    set_hook_name("unlink_hook", 11);
    if(!is_userspace_program())
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

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats returned null");
        return ALLOW;
    }

    event->type = UNLINK;
    if(fill_unlink_event_t(&event->data.unlink, dir, dentry) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_unlink_event_t failed");
        goto allow_event;
    }

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);

    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &unlink_prog_array);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/path_unlink")
int BPF_PROG(unlink_hook_2, const struct path *dir, struct dentry *dentry)
{
    set_hook_name("unlink_hook_2", 13);
    return generic_tail_call();
}

char LICENSE[] SEC("license") = "GPL";