#include "kubernetes/nri_container_cache.hpp"
#include "kubernetes/cgroup_path.hpp"
#include "kubernetes/container_id.hpp"
#include "logger.hpp"

#include <bpf/bpf.h>

#include <mutex>

namespace owlsm::kubernetes
{

void NriContainerCache::setHostRoot(const std::filesystem::path& host_root)
{
    std::unique_lock lock(m_mutex);
    m_host_root = host_root;
}

void NriContainerCache::setMapFd(const int map_fd)
{
    std::unique_lock lock(m_mutex);
    m_map_fd = map_fd;
}

void NriContainerCache::upsert(const char* container_id, const char* pod_uid, const char* cgroups_path)
{
    const std::string raw_id = container_id ? container_id : "";
    std::string raw_uid = pod_uid ? pod_uid : "";
    std::string raw_path = cgroups_path ? cgroups_path : "";
    if (raw_id.empty())
    {
        return;
    }

    const auto truncated_id = ContainerId::toU64(raw_id);
    if (!truncated_id.has_value())
    {
        LOG_INFO("nri upsert skipped: invalid container id");
        return;
    }

    std::filesystem::path host_root;
    {
        std::shared_lock lock(m_mutex);
        host_root = m_host_root;
        if (raw_path.empty())
        {
            const auto pending = m_pending.find(*truncated_id);
            if (pending != m_pending.end())
            {
                raw_path = pending->second.cgroups_path;
                if (raw_uid.empty())
                {
                    raw_uid = pending->second.pod_uid;
                }
            }
        }
    }
    if (host_root.empty())
    {
        LOG_INFO("nri upsert skipped: host cgroup root is unset");
        return;
    }
    if (raw_path.empty())
    {
        LOG_INFO("nri upsert skipped: empty cgroups_path container=" << raw_id);
        return;
    }

    const auto cgroup_id = CgroupPath::cgroupIdFromCriPath(host_root, raw_path);
    if (!cgroup_id.has_value())
    {
        std::unique_lock lock(m_mutex);
        m_pending[*truncated_id] = PendingInsert{raw_uid, raw_path};
        LOG_INFO("nri upsert deferred: cgroup stat failed container=" << raw_id << " path=" << raw_path);
        return;
    }

    std::unique_lock lock(m_mutex);
    if (!raw_uid.empty())
    {
        m_container_id_to_pod_uid[*truncated_id] = raw_uid;
    }
    m_container_id_to_cgroup_id[*truncated_id] = *cgroup_id;
    m_pending.erase(*truncated_id);
    writeBpf(*cgroup_id, *truncated_id);
}

void NriContainerCache::remove(const char* container_id)
{
    const auto truncated_id = ContainerId::toU64(container_id ? container_id : "");
    if (!truncated_id.has_value())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    const auto cgroup_it = m_container_id_to_cgroup_id.find(*truncated_id);
    if (cgroup_it != m_container_id_to_cgroup_id.end())
    {
        deleteBpfIfOwner(cgroup_it->second, *truncated_id);
        m_container_id_to_cgroup_id.erase(cgroup_it);
    }
    m_container_id_to_pod_uid.erase(*truncated_id);
    m_pending.erase(*truncated_id);
}

void NriContainerCache::clear()
{
    std::unique_lock lock(m_mutex);
    for (const auto& [container_id, cgroup_id] : m_container_id_to_cgroup_id)
    {
        deleteBpfIfOwner(cgroup_id, container_id);
    }
    m_container_id_to_cgroup_id.clear();
    m_container_id_to_pod_uid.clear();
    m_pending.clear();
}

std::optional<std::string> NriContainerCache::lookupPodUid(const std::uint64_t container_id) const
{
    std::shared_lock lock(m_mutex);
    const auto it = m_container_id_to_pod_uid.find(container_id);
    if (it == m_container_id_to_pod_uid.end())
    {
        return std::nullopt;
    }
    return it->second;
}

std::optional<std::uint64_t> NriContainerCache::lookupCgroupId(const std::uint64_t container_id) const
{
    std::shared_lock lock(m_mutex);
    const auto it = m_container_id_to_cgroup_id.find(container_id);
    if (it == m_container_id_to_cgroup_id.end())
    {
        return std::nullopt;
    }
    return it->second;
}

std::size_t NriContainerCache::size() const
{
    std::shared_lock lock(m_mutex);
    return m_container_id_to_cgroup_id.size();
}

void NriContainerCache::writeBpf(const std::uint64_t cgroup_id, const std::uint64_t container_id)
{
    if (m_map_fd < 0)
    {
        return;
    }
    if (bpf_map_update_elem(m_map_fd, &cgroup_id, &container_id, BPF_ANY) != 0)
    {
        LOG_INFO("nri bpf update failed cgroup_id=" << cgroup_id);
    }
}

void NriContainerCache::deleteBpfIfOwner(const std::uint64_t cgroup_id, const std::uint64_t container_id)
{
    if (m_map_fd < 0)
    {
        return;
    }

    std::uint64_t current = 0;
    if (bpf_map_lookup_elem(m_map_fd, &cgroup_id, &current) != 0)
    {
        return;
    }
    if (current != container_id)
    {
        return;
    }
    deleteBpf(cgroup_id);
}

void NriContainerCache::deleteBpf(const std::uint64_t cgroup_id)
{
    if (m_map_fd < 0)
    {
        return;
    }
    bpf_map_delete_elem(m_map_fd, &cgroup_id);
}

}
