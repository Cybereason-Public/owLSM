#pragma once

#include "events/event.hpp"
#include "kubernetes/kubernetes_pod_cache.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>

class KubernetesEventEnrichmentTest;

namespace owlsm::events
{

class KubernetesEventEnrichment
{
public:
    KubernetesEventEnrichment() = default;
    void enrich(Kubernetes& kubernetes, const Event& event) const;

private:
    bool shouldLogMiss(const unsigned long long container_id) const;
    bool shouldLogPodUidMiss(const std::string& pod_uid) const;
    static std::string oneLogField(std::string value);
    static void build(Kubernetes& kubernetes,
                      const std::string& node_name,
                      const unsigned long long container_id,
                      const std::optional<std::string>& pod_uid,
                      const std::optional<kubernetes::PodInfo>& pod_info);

    mutable std::mutex m_logged_miss_mutex;
    mutable std::unordered_set<unsigned long long> m_logged_miss_container_ids;
    mutable std::unordered_set<std::string> m_logged_miss_pod_uids;

    friend class ::KubernetesEventEnrichmentTest;
};

}
