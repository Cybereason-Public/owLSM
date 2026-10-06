#pragma once

#ifdef __BPF_KERNEL__
#include "vmlinux.h"
#else
#include <cstddef>
#include <functional>
#endif

struct container_id_t
{
    unsigned long long id;
    bool is_owlsm_container;
    bool is_kube_system;

#ifndef __BPF_KERNEL__
    container_id_t() = default;
    container_id_t(const unsigned long long container_id)
        : id(container_id)
        , is_owlsm_container(false)
        , is_kube_system(false)
    {
    }

    bool operator==(const container_id_t& other) const
    {
        return id == other.id;
    }
#endif
};

#ifndef __BPF_KERNEL__
template<>
struct std::hash<container_id_t>
{
    std::size_t operator()(const container_id_t& container) const noexcept
    {
        return std::hash<unsigned long long>{}(container.id);
    }
};
#endif

struct k8s_config
{
    bool k8s_enabled;
    bool ignore_host_events;
    bool ignore_kube_system_events;
};
