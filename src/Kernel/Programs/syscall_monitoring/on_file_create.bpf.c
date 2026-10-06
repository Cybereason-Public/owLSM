#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "k8s_ignored_events.h"
#include "pids_to_ignore.bpf.h"

#define FILE_CREATE_EVENT
#include "tail_calls_manager.bpf.h"


// catches every thing that SEC("lsm/inode_create") catches. 
SEC("lsm/path_mknod")
int BPF_PROG(fc_hook, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
    set_hook_name("fc_hook", 7);
    if(!is_userspace_program())
    {
        return ALLOW;
    }

    if(is_current_pid_related())
    {
        return ALLOW;
    }

    if (k8s_ignore_current_process())
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed");
        return ALLOW;
    }

    event->type = FILE_CREATE;
    if(fill_file_create_event_t(&event->data.file_create, dir, dentry, mode) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_file_create_event_t failed");
        goto allow_event;
    }

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);

    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &fc_prog_array);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/path_mknod")
int BPF_PROG(fc_hook_2, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
    set_hook_name("fc_hook_2", 9);
    return generic_tail_call();
}


char LICENSE[] SEC("license") = "GPL";