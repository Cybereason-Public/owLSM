#pragma once

#include "kubernetes/nri_container_cache.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <thread>

namespace owlsm::kubernetes
{

class NriPlugin
{
public:
    NriPlugin() = default;
    ~NriPlugin();
    NriPlugin(const NriPlugin&) = delete;
    NriPlugin& operator=(const NriPlugin&) = delete;
    void start();
    void stop();
    void setHostRoot(const std::filesystem::path& host_root);
    void setMapFd(const int map_fd);
    void clear();
    std::size_t size() const;
    std::optional<std::string> lookupPodUid(const std::uint64_t container_id) const;
    void handleUpsert(const char* container_id, const char* pod_uid, const char* cgroups_path);
    void handleRemove(const char* container_id);
    void handleSyncDone();
    void handleDisconnected();

private:
    void startSession();
    bool waitForFirstSync();
    void reconnectLoop();

    NriContainerCache m_cache;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_stopping {false};
    bool m_synced = false;
    bool m_disconnected = false;
    std::thread m_reconnect_thread;
};

}
