#include "kubernetes/kubernetes_pod_cache.hpp"

#include <mutex>
#include <utility>

namespace owlsm::kubernetes
{

void PodIdentityCache::clear()
{
    std::unique_lock lock(m_mutex);
    m_pod_uid_to_info.clear();
    m_container_id_to_pod_uid.clear();
    m_dead_pods.clear();
}

void PodIdentityCache::upsert(PodInfo info)
{
    if (info.uid.empty())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    m_dead_pods.erase(info.uid);

    std::vector<std::string> old_ids;
    const auto existing = m_pod_uid_to_info.find(info.uid);
    if (existing != m_pod_uid_to_info.end())
    {
        old_ids = existing->second.container_ids;
    }

    replaceContainerMappings(info.uid, old_ids, info.container_ids);
    m_pod_uid_to_info[info.uid] = std::move(info);
}

void PodIdentityCache::eraseByUid(const std::string& uid)
{
    if (uid.empty())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    const auto it = m_pod_uid_to_info.find(uid);
    if (it == m_pod_uid_to_info.end())
    {
        return;
    }

    eraseContainerMappings(uid, it->second.container_ids);
    m_dead_pods.put(uid, it->second);
    m_pod_uid_to_info.erase(it);
}

std::size_t PodIdentityCache::livePodCount() const
{
    std::shared_lock lock(m_mutex);
    return m_pod_uid_to_info.size();
}

std::optional<PodInfo> PodIdentityCache::lookupByPodUid(const std::string& uid) const
{
    if (uid.empty())
    {
        return std::nullopt;
    }

    {
        std::shared_lock lock(m_mutex);
        const auto it = m_pod_uid_to_info.find(uid);
        if (it != m_pod_uid_to_info.end())
        {
            return it->second;
        }
    }

    std::unique_lock lock(m_mutex);
    const auto it = m_pod_uid_to_info.find(uid);
    if (it != m_pod_uid_to_info.end())
    {
        return it->second;
    }
    return m_dead_pods.get(uid);
}

std::optional<PodInfo> PodIdentityCache::lookupByContainerId(const std::string& container_id) const
{
    const std::string stripped_id = stripRuntimePrefix(container_id);
    if (stripped_id.empty())
    {
        return std::nullopt;
    }

    {
        std::shared_lock lock(m_mutex);
        const auto container_it = m_container_id_to_pod_uid.find(stripped_id);
        if (container_it != m_container_id_to_pod_uid.end())
        {
            const auto pod_it = m_pod_uid_to_info.find(container_it->second);
            if (pod_it != m_pod_uid_to_info.end())
            {
                return pod_it->second;
            }
        }
    }

    std::unique_lock lock(m_mutex);
    const auto container_it = m_container_id_to_pod_uid.find(stripped_id);
    if (container_it != m_container_id_to_pod_uid.end())
    {
        const auto pod_it = m_pod_uid_to_info.find(container_it->second);
        if (pod_it != m_pod_uid_to_info.end())
        {
            return pod_it->second;
        }
    }
    return lookupDeadByContainerId(stripped_id);
}

void PodIdentityCache::replaceContainerMappings(const std::string& uid,
                                                const std::vector<std::string>& old_ids,
                                                const std::vector<std::string>& new_ids)
{
    eraseContainerMappings(uid, old_ids);
    for (const auto& container_id : new_ids)
    {
        m_container_id_to_pod_uid[container_id] = uid;
    }
}

void PodIdentityCache::eraseContainerMappings(const std::string& uid, const std::vector<std::string>& container_ids)
{
    for (const auto& container_id : container_ids)
    {
        const auto it = m_container_id_to_pod_uid.find(container_id);
        if (it != m_container_id_to_pod_uid.end() && it->second == uid)
        {
            m_container_id_to_pod_uid.erase(it);
        }
    }
}

std::optional<PodInfo> PodIdentityCache::lookupDeadByContainerId(const std::string& container_id) const
{
    return m_dead_pods.findIf([&container_id](const std::string&, const PodInfo& info)
    {
        for (const auto& id : info.container_ids)
        {
            if (id == container_id)
            {
                return true;
            }
        }
        return false;
    });
}

std::string PodIdentityCache::stripRuntimePrefix(const std::string& container_id)
{
    const auto separator = container_id.find("://");
    if (separator == std::string::npos)
    {
        return container_id;
    }
    return container_id.substr(separator + 3);
}

}
