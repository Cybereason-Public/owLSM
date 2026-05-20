#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "protected_processes.bpf.h"

SEC("fentry/wake_up_new_task")
int BPF_PROG(fork_hook, struct task_struct *child_task)
{
    set_hook_name("fork_hook", 9);
    if(!is_userspace_program())
    {
        return ALLOW;
    }
    
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    pid_t ppid = BPF_CORE_READ(current_task, tgid);
    pid_t pid = BPF_CORE_READ(child_task, tgid);

    if (ppid == pid)
    {
        return ALLOW; // New thread.
    }

    if (is_current_pid_protected() == TRUE)
    {
        add_pid_to_protected_processes(pid);
    }

    if(is_current_pid_related() == TRUE)
    {
        add_pid_to_related_pids(pid);
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed");
        return ALLOW;
    }

    if(is_process_in_alive_process_cache(ppid) == FALSE)
    {
        struct process_t *parent_process = allocate_process_t();
        if(!parent_process)
        {
            REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed");
            goto handle_event;
        }
        fill_process_t(parent_process, current_task);

        if(update_process_in_alive_process_cache(ppid, parent_process) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "update_process_in_cache. pid: %d", ppid);
            goto handle_event;
        }
    }

handle_event:
    event->type = FORK;
    if(fill_process_t(&event->process, child_task) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_process_t failed. pid: %d, ppid: %d", pid, ppid);
        goto allow_event;
    }
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);

    if(update_process_in_alive_process_cache(pid, &event->process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "update_process_in_cache. pid: %d", pid);
        goto allow_event;
    }

    bpf_ringbuf_submit(event, 0);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

char LICENSE[] SEC("license") = "GPL";