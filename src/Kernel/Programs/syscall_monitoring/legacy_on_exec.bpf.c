#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"

#define EXEC_EVENT
#define EXEC_MAPS_EXTERN
#include "tail_calls_manager.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PID_MAX_LIMIT);
    __type(key, u32);
    __type(value, u8);
} exec_pids SEC(".maps");

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm)
{
    set_hook_name("bprm_creds_for_exec", 19);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);

    if(is_current_pid_related())
    {
        return ALLOW;
    }

    if(is_system_task())
    {
        return ALLOW;
    }
    if(!is_task_with_mm()) // for kworkers without relevant flags in task->flags
    {
        if(bpf_map_update_elem(&kthread_exec_pids, &pid, &pid, BPF_ANY) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed. pid: %d", pid);
        }
        return ALLOW;
    }

    if(is_process_in_alive_process_cache(pid) == TRUE)
    {
        return ALLOW;
    }

    struct process_t * old_process = allocate_process_t();
    if(!old_process)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed. pid: %d", pid);
        return ALLOW;
    }

    if (fill_current_process_t(old_process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_current_process_t failed pid: %d", pid);
        return ALLOW;
    }

    if(update_process_in_alive_process_cache(pid, old_process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "update_process_in_alive_process_cache failed pid: %d", pid);
    }

    return ALLOW;
}

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
{
    set_hook_name("bprm_committed_creds", 20);
    if(!is_userspace_program())
    {
        return ALLOW;
    }

    if(is_current_pid_related())
    {
        return ALLOW;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);
    char useless_value = 0;
    if(bpf_map_update_elem(&exec_pids, &pid, &useless_value, BPF_NOEXIST) < 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed. pid: %d", pid);
    }

    return ALLOW;
}

SEC("lsm/file_open")
int BPF_PROG(exec_hook, struct file *file)
{
    set_hook_name("exec_hook", 9);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);
    if(!bpf_map_lookup_elem(&exec_pids, &pid))
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats returned null");
        return ALLOW;
    }

    event->type = EXEC;
    struct process_t *old_process = get_process_from_alive_process_cache(pid);
    if(!old_process)
    {
        REPORT_ERROR(GENERIC_ERROR, "get_process_from_alive_process_cache retuned null. pid: %d", pid);
        goto allow_event;
    }

    if(bpf_probe_read_kernel(&event->process, sizeof(struct process_t), old_process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed pid: %d", pid);
        goto allow_event;
    }
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);

    if(fill_current_process_t(&event->data.exec.new_process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_current_process_t failed pid: %d", pid);
        goto allow_event;
    }

    // fill_current_process_t() uses task->real_parent. If the original parent exited and reaped, task->real_parent will be the current parent (likely pid 1) which is not what we want.
    event->data.exec.new_process.ppid = event->process.ppid;
    event->data.exec.new_process.unique_ppid_id = event->process.unique_ppid_id;

    if(update_process_in_alive_process_cache(pid, &event->data.exec.new_process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "update_process_in_alive_process_cache failed pid: %d", pid);
        goto allow_event;
    }
    bpf_map_delete_elem(&exec_pids, &pid);

    store_currently_handled_event(event);
    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &exec_prog_array);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/file_open")
int BPF_PROG(exec_hook_2, struct file *file)
{
    set_hook_name("exec_hook_2", 11);
    return generic_tail_call();
}

char LICENSE[] SEC("license") = "GPL";