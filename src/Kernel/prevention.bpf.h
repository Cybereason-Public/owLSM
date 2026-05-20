#pragma once
#include "common_maps.bpf.h"
#include "process_cache.bpf.h"


statfunc int is_process_created_after_ebpf_attached(unsigned long long* process_start_time)
{
    unsigned int key = 0;
    const unsigned long long *prog_start = bpf_map_lookup_elem(&ebpf_program_start_time, &key);

    return (prog_start && *process_start_time > *prog_start); // greater == younger
}

statfunc void kill_proccesses(enum rule_action action, struct event_t * event)
{
    if(action == BLOCK_KILL_PROCESS)
    {
        bpf_send_signal(SIGKILL);
    }
    else if(action == BLOCK_KILL_PROCESS_KILL_PARENT)
    {
        bpf_send_signal(SIGKILL);
        /*We only kill the parent if we can ensure its the original parent
          In order to ensure that we do:
          1 - Check the ppid is still alive. 
          2 - Check that the unique_ppid_id match. This avoids pid recycle mistake. 
          3 - Check that the ppid start_time is after the ebpf program start_time. 
              This helps us to avoid situation that the original parent exited before ebpf program attached. 
              We can only avoid these situations if the parent was created after the ebpf program attached.
        */
        struct process_t *parent = get_process_from_alive_process_cache(event->process.ppid);
        if(!parent || event->process.unique_ppid_id != parent->unique_process_id)
        {
            return;
        }
        if(!is_process_created_after_ebpf_attached(&parent->start_time))
        {
            return;
        }

        unsigned int ppid = event->process.ppid;
        if (bpf_map_update_elem(&parent_processes_to_kill, &ppid, &ppid, BPF_ANY) < 0)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem. ppid: %d", event->process.ppid);
        }
    }
}