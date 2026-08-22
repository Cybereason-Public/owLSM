#pragma once

#include "lru_cache.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace owlsm::kubernetes
{

struct PodInfo
{
    std::string uid;
    std::string name;
    std::string ns;
    std::map<std::string, std::string> labels;
    std::vector<std::string> container_ids;
};

class PodIdentityCache
{
public:
    static constexpr std::size_t DEAD_POD_LRU_SIZE = 10;

    void clear();
    void upsert(PodInfo info);
    void eraseByUid(const std::string& uid);

    std::size_t livePodCount() const;
    std::optional<PodInfo> lookupByPodUid(const std::string& uid) const;
    std::optional<PodInfo> lookupByContainerId(const std::string& container_id) const;

private:
    void replaceContainerMappings(const std::string& uid,
                                  const std::vector<std::string>& old_ids,
                                  const std::vector<std::string>& new_ids);
    void eraseContainerMappings(const std::string& uid, const std::vector<std::string>& container_ids);
    std::optional<PodInfo> lookupDeadByContainerId(const std::string& container_id) const;
    static std::string stripRuntimePrefix(const std::string& container_id);

    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, PodInfo> m_pod_uid_to_info;
    std::unordered_map<std::string, std::string> m_container_id_to_pod_uid;
    mutable LruCache<std::string, PodInfo> m_dead_pods {DEAD_POD_LRU_SIZE};
};

}
