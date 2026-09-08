#pragma once

#include "kubernetes/kubernetes_pod_cache.hpp"
#include "kubernetes/nri_plugin.hpp"
#include "kubernetes/client_go/owlsm_k8s.h"

#include <atomic>
#include <cstddef>
#include <optional>
#include <string>

namespace owlsm::kubernetes
{

class KubernetesClient
{
public:
    KubernetesClient() = default;
    ~KubernetesClient();
    KubernetesClient(const KubernetesClient&) = delete;
    KubernetesClient& operator=(const KubernetesClient&) = delete;
    KubernetesClient(KubernetesClient&&) = delete;
    KubernetesClient& operator=(KubernetesClient&&) = delete;
    void initialize();
    void startNri(const int cgroup_id_map_fd);
    void destroy();
    bool isReady() const;
    std::size_t cachedPodCount() const;
    std::optional<PodInfo> lookupByPodUid(const std::string& uid) const;
    void handlePodUpsert(const owlsm_k8s_pod* pod);
    void handlePodDelete(const char* uid);

private:
    void confirmCgroupV2();
    std::string readNodeName() const;
    int startClientGo(const std::string& node_name) const;
    std::string describeInitFailure(const int rc) const;
    static PodInfo copyPod(const owlsm_k8s_pod& raw);

    bool m_initialized = false;
    std::atomic<bool> m_cache_enabled {false};
    PodIdentityCache m_cache;
    NriPlugin m_nri_plugin;
};

}
