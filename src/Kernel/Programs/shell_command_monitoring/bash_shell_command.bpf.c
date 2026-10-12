#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "k8s_ignored_events.bpf.h"

SEC("uprobe")
int enter_readline(struct pt_regs *ctx)
{
    set_hook_name("enter_readline", 14);
    
    if(is_current_pid_related())
    {
        return 0;
    }

    if(k8s_ignore_current_process())
    {
        return 0;
    }
    
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    delete_shell_command_from_alive_process(pid);
    return 0;
}

SEC("uretprobe")
int exit_readline(struct pt_regs *ctx)
{
    set_hook_name("exit_readline", 13);

    if(is_current_pid_related())
    {
        return 0;
    }

    if(k8s_ignore_current_process())
    {
        return 0;
    }

    const char *ret = (const char *)PT_REGS_RC(ctx);
    if (!ret)
    {
        return 0;
    }
    
    struct process_t *process = allocate_process_t();
    if (!process)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed");
        return 0;
    }
    if(fill_event_process_from_cache(process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_event_process_from_cache failed");
        return 0;
    }

    int read_len = bpf_probe_read_user_str(process->shell_command.value, sizeof(process->shell_command.value), ret);
    if (read_len < 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user_str failed");
        return 0;
    }
    process->shell_command.length = (read_len > 0) ? (read_len - 1) : 0;
    
    int read_len_minus_1 = LIMIT_PATH_SIZE(process->shell_command.length - 1);
    if (process->shell_command.length > 0 && process->shell_command.value[read_len_minus_1] == '\n')
    {
        process->shell_command.value[read_len_minus_1] = '\0';
        process->shell_command.length = read_len_minus_1;
    }
    
    update_shell_command_in_process(process->pid, &process->shell_command);
    return 0;
}