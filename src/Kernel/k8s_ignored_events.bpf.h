#pragma once
#include "fill_event_structs.bpf.h"

statfunc bool should_ignore_container(const struct container_id_t *container_id)
{
    if (!k8s_config.k8s_enabled)
    {
        return false;
    }
    
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

bool k8s_ignore_current_process(void);
