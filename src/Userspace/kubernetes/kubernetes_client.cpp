#include "kubernetes/kubernetes_client.hpp"
#include "kubernetes/client_go/owlsm_k8s.h"
#include "globals/global_objects.hpp"
#include "logger.hpp"

#include <cstdlib>
#include <stdexcept>
#include <string>

extern "C" void owlsmK8sOnPodUpsert(const owlsm_k8s_pod* pod);
extern "C" void owlsmK8sOnPodDelete(const char* uid);

namespace owlsm::kubernetes
{

constexpr int CACHE_SYNC_TIMEOUT_MS = 30000;

KubernetesClient::~KubernetesClient()
{
    destroy();
}

void KubernetesClient::initialize()
{
    if (!owlsm::globals::g_config.kubernetes.enabled || m_initialized)
    {
        return;
    }

    m_cache.clear();
    m_cache_enabled.store(true);
    const auto rc = startClientGo(readNodeName());
    if (rc != 0)
    {
        m_cache_enabled.store(false);
        m_cache.clear();
        throw std::runtime_error(describeInitFailure(rc));
    }

    m_initialized = true;
    LOG_INFO("client-go Kubernetes client ready cached_pods=" << cachedPodCount());
}

void KubernetesClient::destroy()
{
    m_cache_enabled.store(false);
    m_initialized = false;
    owlsm_k8s_destroy();
    m_cache.clear();
}

bool KubernetesClient::isReady() const
{
    return m_initialized;
}

std::size_t KubernetesClient::cachedPodCount() const
{
    return m_cache.livePodCount();
}

std::optional<PodInfo> KubernetesClient::lookupByPodUid(const std::string& uid) const
{
    return m_cache.lookupByPodUid(uid);
}

std::optional<PodInfo> KubernetesClient::lookupByContainerId(const std::string& container_id) const
{
    return m_cache.lookupByContainerId(container_id);
}

void KubernetesClient::handlePodUpsert(const owlsm_k8s_pod* pod)
{
    if (!m_cache_enabled.load() || pod == nullptr)
    {
        return;
    }
    m_cache.upsert(copyPod(*pod));
}

void KubernetesClient::handlePodDelete(const char* uid)
{
    if (!m_cache_enabled.load() || uid == nullptr)
    {
        return;
    }
    m_cache.eraseByUid(uid);
}

std::string KubernetesClient::readNodeName() const
{
    const auto* node_name = std::getenv("NODE_NAME");
    if (node_name == nullptr)
    {
        LOG_WARN("NODE_NAME is unset; pod informer will not be filtered to this node");
        return {};
    }
    return node_name;
}

int KubernetesClient::startClientGo(const std::string& node_name) const
{
    LOG_INFO("Initializing client-go Kubernetes client");
    return owlsm_k8s_init(node_name.c_str(), CACHE_SYNC_TIMEOUT_MS, &owlsmK8sOnPodUpsert, &owlsmK8sOnPodDelete);
}

std::string KubernetesClient::describeInitFailure(const int rc) const
{
    auto error_msg = "client-go init failed with code " + std::to_string(rc);
    if (rc == -1)
    {
        error_msg += " (in-cluster config)";
    }
    else if (rc == -2)
    {
        error_msg += " (pod informer cache sync timeout)";
    }
    return error_msg;
}

PodInfo KubernetesClient::copyPod(const owlsm_k8s_pod& raw)
{
    PodInfo info;
    info.uid = raw.uid ? raw.uid : "";
    info.name = raw.name ? raw.name : "";
    info.ns = raw.ns ? raw.ns : "";

    if (raw.labels != nullptr)
    {
        for (int i = 0; i < raw.label_count; ++i)
        {
            info.labels.emplace(raw.labels[i].key ? raw.labels[i].key : "", raw.labels[i].value ? raw.labels[i].value : "");
        }
    }
    if (raw.container_ids != nullptr)
    {
        for (int i = 0; i < raw.container_id_count; ++i)
        {
            info.container_ids.push_back(raw.container_ids[i] ? raw.container_ids[i] : "");
        }
    }
    return info;
}

}

extern "C" void owlsmK8sOnPodUpsert(const owlsm_k8s_pod* pod)
{
    owlsm::globals::g_kubernetes_client.handlePodUpsert(pod);
}

extern "C" void owlsmK8sOnPodDelete(const char* uid)
{
    owlsm::globals::g_kubernetes_client.handlePodDelete(uid);
}
