#pragma once
#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "common_maps.bpf.h"

#define PF_VCPU			0x00000001
#define PF_WQ_WORKER    0x00000020
#define PF_KTHREAD		0x00200000

statfunc void add_pid_to_related_pids(int pid)
{
    unsigned int key = pid;
    int one = 1;
    if(bpf_map_update_elem(&program_related_pids, &key, &one, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed. pid: %d", pid);
    }
}

statfunc void add_current_pid_to_related_pids(void)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    int one = 1;   
    if(bpf_map_update_elem(&program_related_pids, &pid, &one, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed. pid: %d", pid);
    }
}

statfunc void remove_current_pid_from_related_pids(void)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    if(bpf_map_delete_elem(&program_related_pids, &pid) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_delete_elem. pid: %d", pid);
    }
}

statfunc int is_current_pid_related(void)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&program_related_pids, &pid) != NULL ? TRUE : FALSE;
}

statfunc int is_system_task(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, pid) <= 1) return TRUE; // init process & per‐CPU idle “swapper” task.
    if (BPF_CORE_READ(task, flags) & (PF_VCPU | PF_WQ_WORKER | PF_KTHREAD )) return TRUE;
    return FALSE;
}

statfunc int is_task_with_mm(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, mm) != NULL ? TRUE : FALSE; // No virtual memory manager context, means kthread.
}

statfunc int is_userspace_program(void)
{
    return is_task_with_mm() && !is_system_task();
}