#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "active_shells.bpf.h"
#include "k8s_ignored_events.bpf.h"

#define HOOK_ZLEENTRY_ENTERED 0x01
#define HOOK_PARSE_EVENT_ENTERED 0x02
#define HOOK_BOTH_ENTERED (HOOK_ZLEENTRY_ENTERED | HOOK_PARSE_EVENT_ENTERED)

statfunc void check_and_clear_if_both_hooks_entered(unsigned char current_hook_bit)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned char *existing_bits = bpf_map_lookup_elem(&active_shell_pids, &pid);
    unsigned char new_bits;
    
    if(existing_bits)
    {
        new_bits = *existing_bits | current_hook_bit;
    }
    else
    {
        new_bits = current_hook_bit;
    }
    
    if(new_bits == HOOK_BOTH_ENTERED)
    {
        delete_shell_command_from_alive_process(pid);
        delete_pid_from_active_shell_pids(pid);
    }
    else
    {
        bpf_map_update_elem(&active_shell_pids, &pid, &new_bits, BPF_ANY);
    }
}

SEC("uprobe")
int enter_zleentry(struct pt_regs *ctx)
{
    set_hook_name("enter_zleentry", 14);
    
    if(is_current_pid_related())
    {
        return 0;
    }

    if(k8s_ignore_current_process())
    {
        return 0;
    }
    
    check_and_clear_if_both_hooks_entered(HOOK_ZLEENTRY_ENTERED);
    return 0;
}

SEC("uprobe")
int enter_parse_event(struct pt_regs *ctx)
{
    set_hook_name("enter_parse_event", 17);
    
    if(is_current_pid_related())
    {
        return 0;
    }
    
    if(k8s_ignore_current_process())
    {
        return 0;
    }

    check_and_clear_if_both_hooks_entered(HOOK_PARSE_EVENT_ENTERED);
    return 0;
}

// Code duplication with exit_readline
SEC("uretprobe")
int exit_zleentry(struct pt_regs *ctx)
{
    set_hook_name("exit_zleentry", 13);

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