#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "debug_utils.h"
#include "k8s_ignored_events.bpf.h"

#define RENAME_EVENT
#include "tail_calls_manager.bpf.h"

// On kernel < 5.19, there was no argument "flags" for this hook. It was seperated to two events when RENAME_EXCHANGE flag was set.
SEC("lsm/path_rename")
int BPF_PROG(rename_hook, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
    set_hook_name("rename_hook", 11);
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

    event->type = RENAME;
    if(fill_rename_event_t(&event->data.rename, old_dir, old_dentry, new_dir, new_dentry) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_rename_event_t failed");
        goto allow_event;
    }
    event->data.rename.flags = flags;

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);

    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &rename_prog_array);
    return ALLOW;
    
allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/path_rename")
int BPF_PROG(rename_hook_2, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
    set_hook_name("rename_hook_2", 13);
    return generic_tail_call();
}

char LICENSE[] SEC("license") = "GPL";