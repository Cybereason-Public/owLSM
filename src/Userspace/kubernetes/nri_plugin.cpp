#include "kubernetes/nri_plugin.hpp"
#include "kubernetes/client_go/owlsm_k8s.h"
#include "logger.hpp"

#include <chrono>
#include <stdexcept>

namespace owlsm::kubernetes
{

constexpr int FIRST_SYNC_TIMEOUT_MS = 5000;

NriPlugin* g_nri_plugin = nullptr;

extern "C" void owlsmK8sOnNriUpsert(const char* container_id, const char* pod_uid, const char* cgroups_path)
{
    if (g_nri_plugin != nullptr)
    {
        g_nri_plugin->handleUpsert(container_id, pod_uid, cgroups_path);
    }
}

extern "C" void owlsmK8sOnNriRemove(const char* container_id)
{
    if (g_nri_plugin != nullptr)
    {
        g_nri_plugin->handleRemove(container_id);
    }
}

extern "C" void owlsmK8sOnNriSyncDone(void)
{
    if (g_nri_plugin != nullptr)
    {
        g_nri_plugin->handleSyncDone();
    }
}

extern "C" void owlsmK8sOnNriDisconnected(void)
{
    if (g_nri_plugin != nullptr)
    {
        g_nri_plugin->handleDisconnected();
    }
}

NriPlugin::~NriPlugin()
{
    stop();
}

void NriPlugin::start()
{
    m_stopping.store(false);
    g_nri_plugin = this;
    startSession();
    if (!waitForFirstSync())
    {
        owlsm_k8s_nri_stop();
        throw std::runtime_error("NRI first Synchronize timed out");
    }
    m_reconnect_thread = std::thread(&NriPlugin::reconnectLoop, this);
}

void NriPlugin::stop()
{
    m_stopping.store(true);
    {
        std::lock_guard lock(m_mutex);
        m_cv.notify_all();
    }
    owlsm_k8s_nri_stop();
    if (m_reconnect_thread.joinable())
    {
        m_reconnect_thread.join();
    }
    g_nri_plugin = nullptr;
}

void NriPlugin::setHostRoot(const std::filesystem::path& host_root)
{
    m_cache.setHostRoot(host_root);
}

void NriPlugin::setMapFd(const int map_fd)
{
    m_cache.setMapFd(map_fd);
}

void NriPlugin::clear()
{
    m_cache.clear();
}

std::size_t NriPlugin::size() const
{
    return m_cache.size();
}

void NriPlugin::handleUpsert(const char* container_id, const char* pod_uid, const char* cgroups_path)
{
    m_cache.upsert(container_id, pod_uid, cgroups_path);
}

void NriPlugin::handleRemove(const char* container_id)
{
    m_cache.remove(container_id);
}

void NriPlugin::handleSyncDone()
{
    std::lock_guard lock(m_mutex);
    m_synced = true;
    m_cv.notify_all();
}

void NriPlugin::handleDisconnected()
{
    std::lock_guard lock(m_mutex);
    m_disconnected = true;
    m_cv.notify_all();
}

void NriPlugin::startSession()
{
    {
        std::lock_guard lock(m_mutex);
        m_synced = false;
        m_disconnected = false;
    }
    const auto rc = owlsm_k8s_nri_start(&owlsmK8sOnNriUpsert, &owlsmK8sOnNriRemove,
                                        &owlsmK8sOnNriSyncDone, &owlsmK8sOnNriDisconnected);
    if (rc != 0)
    {
        throw std::runtime_error("NRI connect failed with code " + std::to_string(rc));
    }
}

bool NriPlugin::waitForFirstSync()
{
    std::unique_lock lock(m_mutex);
    return m_cv.wait_for(lock, std::chrono::milliseconds(FIRST_SYNC_TIMEOUT_MS), [this]()
    {
        return m_synced || m_stopping.load();
    }) && m_synced;
}

void NriPlugin::reconnectLoop()
{
    while (!m_stopping.load())
    {
        {
            std::unique_lock lock(m_mutex);
            m_cv.wait(lock, [this]()
            {
                return m_disconnected || m_stopping.load();
            });
            if (m_stopping.load())
            {
                return;
            }
            m_disconnected = false;
        }

        LOG_WARN("NRI disconnected; clearing maps and reconnecting");
        m_cache.clear();
        owlsm_k8s_nri_stop();
        if (m_stopping.load())
        {
            return;
        }

        try
        {
            startSession();
            if (!waitForFirstSync() && !m_stopping.load())
            {
                LOG_ERROR("NRI reconnect Synchronize timed out");
                owlsm_k8s_nri_stop();
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("NRI reconnect failed: " << e.what());
        }
    }
}

}
