#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace owlsm::kubernetes
{

struct PodInfo
{
    std::string uid;
    std::string name;
    std::string ns;
    std::map<std::string, std::string> labels;
};

class PodIdentityCache
{
public:
    void clear();
    void upsert(PodInfo info);
    void eraseByUid(const std::string& uid);

    std::size_t livePodCount() const;
    std::optional<PodInfo> lookupByPodUid(const std::string& uid) const;

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, PodInfo> m_pod_uid_to_info;
};

}
