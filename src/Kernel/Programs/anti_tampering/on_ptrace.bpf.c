#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "protected_processes.bpf.h"
#include "prevention.bpf.h"

#define PTRACE_MODE_ATTACH 0x02

const volatile int anti_tampering_ptrace_action;

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_hook, struct task_struct *child, unsigned int mode)
{
    set_hook_name("ptrace_hook", 11);

    if (!(mode & PTRACE_MODE_ATTACH))
    {
        return ALLOW;
    }

    unsigned int sender_pid = bpf_get_current_pid_tgid() >> 32;
    if (sender_pid <= 1)
    {
        return ALLOW;
    }

    unsigned int receiver_pid = BPF_CORE_READ(child, tgid);
    if (is_pid_protected(receiver_pid) != TRUE)
    {
        return ALLOW;
    }

    if (is_current_pid_protected() == TRUE)
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats returned null");
        return ALLOW;
    }

    event->type = PTRACE;
    event->action = anti_tampering_ptrace_action;
    event->data.ptrace.mode = mode;

    if (fill_event_process_from_cache(&event->process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_event_process_from_cache failed. sender pid: %d", sender_pid);
        goto allow_event;
    }
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);

    if (fill_event_process_from_cache_for_task(&event->data.ptrace.process, child) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_event_process_from_cache_for_task failed for receiver. pid: %d", receiver_pid);
        goto allow_event;
    }

    if (event->action == BLOCK_KILL_PROCESS || event->action == BLOCK_KILL_PROCESS_KILL_PARENT)
    {
        kill_proccesses(event->action, event);
    }

    int verdict = ALLOW;
    if (event->action == BLOCK_EVENT || event->action == BLOCK_KILL_PROCESS || event->action == BLOCK_KILL_PROCESS_KILL_PARENT)
    {
        verdict = DENY;
    }

    if (event->action != EXCLUDE_EVENT)
    {
        bpf_ringbuf_submit(event, 0);
    }
    else
    {
        bpf_ringbuf_discard(event, 0);
    }
    return verdict;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

char LICENSE[] SEC("license") = "GPL";
