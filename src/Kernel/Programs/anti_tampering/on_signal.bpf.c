#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "protected_processes.bpf.h"
#include "prevention.bpf.h"

#define SEND_SIG_NOINFO ((struct kernel_siginfo *)0)
#define SEND_SIG_PRIV   ((struct kernel_siginfo *)1)

const volatile int anti_tampering_signals_action;

SEC("lsm/task_kill")
int BPF_PROG(signal_hook, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    set_hook_name("signal_hook", 11);

    if (info == SEND_SIG_NOINFO || info == SEND_SIG_PRIV)
    {
        return ALLOW;
    }

    int si_code = 0;
    bpf_probe_read_kernel(&si_code, sizeof(si_code), &info->si_code);
    if (si_code > 0)
    {
        return ALLOW;
    }

    unsigned int sender_pid = bpf_get_current_pid_tgid() >> 32;
    if (sender_pid <= 1)
    {
        return ALLOW;
    }

    unsigned int receiver_pid = BPF_CORE_READ(p, tgid);
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

    event->type = SIGNAL;
    event->action = anti_tampering_signals_action;
    event->data.signal.signal = sig;

    if (fill_event_process_from_cache(&event->process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_event_process_from_cache failed. sender pid: %d", sender_pid);
        goto allow_event;
    }
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);

    if (fill_event_process_from_cache_for_task(&event->data.signal.process, p) != SUCCESS)
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
