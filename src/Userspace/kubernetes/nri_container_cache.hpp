#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

class NriContainerCacheTest;

namespace owlsm::kubernetes
{

class NriContainerCache
{
public:
    void setHostRoot(const std::filesystem::path& host_root);
    void setMapFd(const int map_fd);
    void upsert(const char* container_id, const char* pod_uid, const char* cgroups_path);
    void remove(const char* container_id);
    void clear();

    std::optional<std::string> lookupPodUid(const std::uint64_t container_id) const;
    std::optional<std::uint64_t> lookupCgroupId(const std::uint64_t container_id) const;
    std::size_t size() const;

private:
    void writeBpf(const std::uint64_t cgroup_id, const std::uint64_t container_id);
    void deleteBpfIfOwner(const std::uint64_t cgroup_id, const std::uint64_t container_id);
    void deleteBpf(const std::uint64_t cgroup_id);

    struct PendingInsert
    {
        std::string pod_uid;
        std::string cgroups_path;
    };

    mutable std::shared_mutex m_mutex;
    std::filesystem::path m_host_root;
    int m_map_fd = -1;
    std::unordered_map<std::uint64_t, std::string> m_container_id_to_pod_uid;
    std::unordered_map<std::uint64_t, std::uint64_t> m_container_id_to_cgroup_id;
    std::unordered_map<std::uint64_t, PendingInsert> m_pending;

    friend class ::NriContainerCacheTest;
};

}
