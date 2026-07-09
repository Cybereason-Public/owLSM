#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"

#define EXEC_EVENT
#include "tail_calls_manager.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct command_line_t);
} cmd_scratch SEC(".maps");

statfunc void capture_execve_cmd(const char *const *argv)
{
    int key = 0;
    struct command_line_t *temp_cmd = bpf_map_lookup_elem(&cmd_scratch, &key);
    if(!temp_cmd)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem failed");
        return;
    }
    if(bpf_probe_read_kernel(temp_cmd, sizeof(struct command_line_t), &empty_command_line_t) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel(empty_command_line_t) failed");
        return;
    }

    if(get_cmd_from_user_argv(temp_cmd, argv) != SUCCESS)
    {
        return;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);

    if(bpf_map_update_elem(&pid_to_exec_cmd_map, &pid, temp_cmd, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed. pid: %d", pid);
        return;
    }
}

statfunc void ensure_old_process_in_process_cache(pid_t pid)
{
    if(is_process_in_alive_process_cache(pid) == TRUE)
    {
        return;
    }

    struct process_t * old_process = allocate_process_t();
    if(!old_process)
    {
        return;
    }

    if (fill_current_process_t(old_process) != SUCCESS)
    {
        return;
    }

    update_process_in_alive_process_cache(pid, old_process);
}

statfunc void sys_enter_exec(const char *const *argv)
{
    if(!is_userspace_program())
    {
        return;
    }

    if(is_current_pid_related())
    {
        return;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);

    capture_execve_cmd(argv);
    ensure_old_process_in_process_cache(pid);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    set_hook_name("sys_enter_execve", 16);
    sys_enter_exec(get_execve_argv_from_ctx(ctx));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    set_hook_name("sys_enter_execveat", 18);
    sys_enter_exec(get_execveat_argv_from_ctx(ctx));
    return 0;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm)
{
    set_hook_name("bprm_creds_from_file", 20);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);

    struct command_line_t * cmd = bpf_map_lookup_elem(&pid_to_exec_cmd_map, &pid);
    if(!cmd)
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

    if(fill_process_t_from_bprm(&event->data.exec.new_process, bprm, cmd) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_process_t_from_bprm failed pid: %d", pid);
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

    bpf_map_delete_elem(&pid_to_exec_cmd_map, &pid);

    store_currently_handled_event(event);
    bpf_ringbuf_discard(event, 0);
    reset_tail_counter();
    do_tail_call(ctx, &exec_prog_array);
    return ALLOW;

allow_event:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file_2, struct linux_binprm *bprm)
{
    set_hook_name("bprm_creds_from_file_2", 22);
    return generic_tail_call();
}

char LICENSE[] SEC("license") = "GPL";