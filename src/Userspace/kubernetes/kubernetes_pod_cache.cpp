#include "kubernetes/kubernetes_pod_cache.hpp"

#include <mutex>
#include <utility>

namespace owlsm::kubernetes
{

void PodIdentityCache::clear()
{
    std::unique_lock lock(m_mutex);
    m_pod_uid_to_info.clear();
}

void PodIdentityCache::upsert(PodInfo info)
{
    if (info.uid.empty())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    m_pod_uid_to_info[info.uid] = std::move(info);
}

void PodIdentityCache::eraseByUid(const std::string& uid)
{
    if (uid.empty())
    {
        return;
    }

    std::unique_lock lock(m_mutex);
    m_pod_uid_to_info.erase(uid);
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

    std::shared_lock lock(m_mutex);
    const auto it = m_pod_uid_to_info.find(uid);
    if (it == m_pod_uid_to_info.end())
    {
        return std::nullopt;
    }
    return it->second;
}

}
