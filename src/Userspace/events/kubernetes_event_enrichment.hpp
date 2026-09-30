#pragma once

#include "events/event.hpp"
#include "kubernetes/kubernetes_pod_cache.hpp"

#include <optional>
#include <string>

class KubernetesEventEnrichmentTest;

namespace owlsm::events
{

class KubernetesEventEnrichment
{
public:
    KubernetesEventEnrichment() = default;
    void enrich(Kubernetes& kubernetes, const unsigned long long container_id) const;

private:
    static void build(Kubernetes& kubernetes,
                      const std::string& node_name,
                      const unsigned long long container_id,
                      const std::optional<std::string>& pod_uid,
                      const std::optional<kubernetes::PodInfo>& pod_info);

    friend class ::KubernetesEventEnrichmentTest;
};

}
