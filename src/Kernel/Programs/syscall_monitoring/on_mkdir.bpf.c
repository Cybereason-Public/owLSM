#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "k8s_ignored_events.bpf.h"

#define MKDIR_EVENT
#include "tail_calls_manager.bpf.h"

SEC("lsm/path_mkdir")
int BPF_PROG(mkdir_hook, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    set_hook_name("mkdir_hook", 10);
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
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed");
        return ALLOW;
    }

    event->type = MKDIR;
    umode_t mkdir_mode = mode | S_IFDIR; // path_mkdir receives mode without S_IFDIR
    if(fill_file_create_event_t(&event->data.mkdir, dir, dentry, mkdir_mode) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_file_create_event_t failed");
        goto allow_event;
    }

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);

    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &mkdir_prog_array);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/path_mkdir")
int BPF_PROG(mkdir_hook_2, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    set_hook_name("mkdir_hook_2", 12);
    return generic_tail_call();
}


char LICENSE[] SEC("license") = "GPL";
