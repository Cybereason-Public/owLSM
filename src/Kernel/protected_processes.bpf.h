#pragma once
#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "common_maps.bpf.h"

statfunc void add_pid_to_protected_processes(int pid)
{
    unsigned int key = pid;
    int one = 1;
    if (bpf_map_update_elem(&protected_processes, &key, &one, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem protected_processes failed. pid: %d", pid);
    }
}

statfunc void remove_current_pid_from_protected_processes(void)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_delete_elem(&protected_processes, &pid) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_delete_elem protected_processes. pid: %d", pid);
    }
}

statfunc int is_pid_protected(unsigned int pid)
{
    return bpf_map_lookup_elem(&protected_processes, &pid) != NULL ? TRUE : FALSE;
}

statfunc int is_current_pid_protected(void)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    return is_pid_protected(pid);
}
