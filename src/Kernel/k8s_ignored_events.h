#pragma once
#include "fill_event_structs.bpf.h"

statfunc bool should_ignore_container(const struct container_id_t *container_id)
{
    if (k8s_config.ignore_host_events && container_id->id == 0)
    {
        return true;
    }

    if (k8s_config.ignore_kube_system_events && container_id->is_kube_system)
    {
        return true;
    }

    if (container_id->is_owlsm_container)
    {
        return true;
    }

    return false;
}

statfunc bool try_to_find_container_and_see_if_should_ignore(void)
{
    const struct container_id_t *container_id = get_container_id_t_of_current_task();
    if (!container_id)
    {
        // if no container, it's a host process.
        return k8s_config.ignore_host_events;
    }
    return should_ignore_container(container_id);
}

statfunc bool k8s_ignore_process(u32 pid)
{
    if (!k8s_config.k8s_enabled)
    {
        return false;
    }

    struct process_t *process = get_process_from_alive_process_cache(pid);
    if (process)
    {
        return should_ignore_container(&process->container_id);
    }

    if (pid == bpf_get_current_pid_tgid() >> 32)
    {
        return try_to_find_container_and_see_if_should_ignore();
    }

    return false;
}

statfunc bool k8s_ignore_current_process(void)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return k8s_ignore_process(pid);
}