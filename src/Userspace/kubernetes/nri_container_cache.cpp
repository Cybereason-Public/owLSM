#include "kubernetes/nri_container_cache.hpp"
#include "kubernetes/cgroup_path.hpp"
#include "kubernetes/container_id.hpp"
#include "logger.hpp"

#include <bpf/bpf.h>

#include <mutex>
#include <sstream>

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
    const auto pod_it = m_container_id_to_pod_uid.find(*truncated_id);
    const auto cgroup_it = m_container_id_to_cgroup_id.find(*truncated_id);
    const bool uid_changed = !raw_uid.empty() && (pod_it == m_container_id_to_pod_uid.end() || pod_it->second != raw_uid);
    const bool cgroup_changed = cgroup_it == m_container_id_to_cgroup_id.end() || cgroup_it->second != *cgroup_id;
    if (uid_changed || cgroup_changed)
    {
        LOG_INFO("nri upsert container=" << raw_id
            << " truncated=" << *truncated_id
            << " pod_uid=" << raw_uid
            << " cgroup_id=" << *cgroup_id
            << " path=" << raw_path);
    }
    if (!raw_uid.empty())
    {
        m_container_id_to_pod_uid[*truncated_id] = raw_uid;
    }
    m_container_id_to_cgroup_id[*truncated_id] = *cgroup_id;
    m_pending.erase(*truncated_id);
    UpdateBpfMap(*cgroup_id, *truncated_id);
}

void NriContainerCache::remove(const char* container_id)
{
    const auto truncated_id = ContainerId::toU64(container_id ? container_id : "");
    if (!truncated_id.has_value())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    std::string removed_pod_uid;
    bool had_row = false;
    const auto cgroup_it = m_container_id_to_cgroup_id.find(*truncated_id);
    if (cgroup_it != m_container_id_to_cgroup_id.end())
    {
        had_row = true;
        deleteEntryFromBpfMapIfOwner(cgroup_it->second, *truncated_id);
        m_container_id_to_cgroup_id.erase(cgroup_it);
    }
    const auto pod_it = m_container_id_to_pod_uid.find(*truncated_id);
    if (pod_it != m_container_id_to_pod_uid.end())
    {
        had_row = true;
        removed_pod_uid = pod_it->second;
        m_removed_container_id_to_pod_uid.put(*truncated_id, pod_it->second);
        m_container_id_to_pod_uid.erase(pod_it);
    }
    const auto pending_it = m_pending.find(*truncated_id);
    if (pending_it != m_pending.end())
    {
        had_row = true;
        if (removed_pod_uid.empty())
        {
            removed_pod_uid = pending_it->second.pod_uid;
        }
    }
    m_pending.erase(*truncated_id);
    if (had_row)
    {
        LOG_INFO("nri remove container=" << (container_id ? container_id : "")
            << " truncated=" << *truncated_id
            << " pod_uid=" << removed_pod_uid);
    }
}

void NriContainerCache::clear()
{
    std::unique_lock lock(m_mutex);
    for (const auto& [container_id, cgroup_id] : m_container_id_to_cgroup_id)
    {
        deleteEntryFromBpfMapIfOwner(cgroup_id, container_id);
    }
    m_container_id_to_cgroup_id.clear();
    m_container_id_to_pod_uid.clear();
    m_removed_container_id_to_pod_uid.clear();
    m_pending.clear();
}

std::optional<std::string> NriContainerCache::lookupPodUid(const std::uint64_t container_id) const
{
    {
        std::shared_lock lock(m_mutex);
        const auto it = m_container_id_to_pod_uid.find(container_id);
        if (it != m_container_id_to_pod_uid.end())
        {
            return it->second;
        }
    }
    std::unique_lock lock(m_mutex);
    const auto it = m_container_id_to_pod_uid.find(container_id);
    if (it != m_container_id_to_pod_uid.end())
    {
        return it->second;
    }
    return m_removed_container_id_to_pod_uid.get(container_id);
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

std::string NriContainerCache::describeLookupState(const std::uint64_t container_id) const
{
    std::shared_lock lock(m_mutex);
    const auto pod_it = m_container_id_to_pod_uid.find(container_id);
    const auto cgroup_it = m_container_id_to_cgroup_id.find(container_id);
    const auto pending_it = m_pending.find(container_id);
    std::ostringstream state;
    state << "in_pod_map=" << (pod_it != m_container_id_to_pod_uid.end() ? 1 : 0)
        << " in_cgroup_map=" << (cgroup_it != m_container_id_to_cgroup_id.end() ? 1 : 0)
        << " mapped_cgroup_id=" << (cgroup_it != m_container_id_to_cgroup_id.end() ? cgroup_it->second : 0)
        << " pending=" << (pending_it != m_pending.end() ? 1 : 0)
        << " pending_pod_uid=" << (pending_it != m_pending.end() ? pending_it->second.pod_uid : "")
        << " pending_path=" << (pending_it != m_pending.end() ? pending_it->second.cgroups_path : "")
        << " in_removed_lru=" << (m_removed_container_id_to_pod_uid.contains(container_id) ? 1 : 0);
    return state.str();
}

std::size_t NriContainerCache::size() const
{
    std::shared_lock lock(m_mutex);
    return m_container_id_to_cgroup_id.size();
}

void NriContainerCache::UpdateBpfMap(const std::uint64_t cgroup_id, const std::uint64_t container_id)
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

void NriContainerCache::deleteEntryFromBpfMapIfOwner(const std::uint64_t cgroup_id, const std::uint64_t container_id)
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
    deleteEntryFromBpfMap(cgroup_id);
}

void NriContainerCache::deleteEntryFromBpfMap(const std::uint64_t cgroup_id)
{
    if (m_map_fd < 0)
    {
        return;
    }
    bpf_map_delete_elem(m_map_fd, &cgroup_id);
}

}
