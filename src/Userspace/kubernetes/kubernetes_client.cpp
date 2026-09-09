#include "kubernetes/kubernetes_client.hpp"
#include "kubernetes/cgroup_path.hpp"
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
    m_nri_plugin.clear();
    m_cache_enabled.store(true);
    confirmCgroupV2();
    m_node_name = readNodeName();
    const auto rc = startClientGo(m_node_name);
    if (rc != 0)
    {
        m_cache_enabled.store(false);
        m_cache.clear();
        throw std::runtime_error(describeInitFailure(rc));
    }

    m_initialized = true;
    LOG_INFO("client-go Kubernetes client ready cached_pods=" << cachedPodCount());
}

void KubernetesClient::startNri(const int cgroup_id_map_fd)
{
    if (!m_initialized)
    {
        throw std::runtime_error("NRI start requires Kubernetes client init");
    }
    m_nri_plugin.setMapFd(cgroup_id_map_fd);
    m_nri_plugin.start();
    LOG_INFO("NRI plugin ready containers=" << m_nri_plugin.size());
}

void KubernetesClient::destroy()
{
    m_cache_enabled.store(false);
    m_initialized = false;
    m_nri_plugin.stop();
    m_nri_plugin.clear();
    owlsm_k8s_destroy();
    m_cache.clear();
    m_node_name.clear();
}

bool KubernetesClient::isReady() const
{
    return m_initialized;
}

std::size_t KubernetesClient::cachedPodCount() const
{
    return m_cache.livePodCount();
}

std::string KubernetesClient::nodeName() const
{
    return m_node_name;
}

std::optional<std::string> KubernetesClient::lookupPodUid(const std::uint64_t container_id) const
{
    return m_nri_plugin.lookupPodUid(container_id);
}

std::optional<PodInfo> KubernetesClient::lookupByPodUid(const std::string& uid) const
{
    return m_cache.lookupByPodUid(uid);
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

void KubernetesClient::confirmCgroupV2()
{
    const auto host_proc_path = owlsm::globals::g_config.kubernetes.root_proc_path.empty() 
        ? std::filesystem::path(owlsm::globals::DEFAULT_HOST_PROC_DIR) 
            : std::filesystem::path(owlsm::globals::g_config.kubernetes.root_proc_path);
    
    CgroupPath::throwIfNotCgroupV2(host_proc_path);
    m_nri_plugin.setHostRoot(host_proc_path);
    LOG_INFO("cgroup v2 host root=" << host_proc_path.string());
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
