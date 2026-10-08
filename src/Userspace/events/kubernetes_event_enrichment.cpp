#include "events/kubernetes_event_enrichment.hpp"
#include "globals/global_objects.hpp"
#include "logger.hpp"

#include <3rd_party/magic_enum/magic_enum.hpp>

namespace owlsm::events
{

void KubernetesEventEnrichment::enrich(Kubernetes& kubernetes, const Event& event) const
{
    const unsigned long long container_id = event.process.container_id;
    std::optional<std::string> pod_uid;
    std::optional<kubernetes::PodInfo> pod_info;
    if (container_id != 0)
    {
        pod_uid = owlsm::globals::g_kubernetes_client.lookupPodUid(container_id);
        if (!pod_uid.has_value() || pod_uid->empty())
        {
            if (shouldLogMiss(container_id))
            {
                LOG_ERROR("container_id_to_pod_uid miss container_id=" << container_id
                    << " event=" << magic_enum::enum_name(event.type)
                    << " pid=" << event.process.pid
                    << " ns_pid=" << event.process.ns_pid
                    << " cgroup_id=" << event.process.cgroup_id
                    << " exe=" << oneLogField(event.process.file.path.value)
                    << " cmd=" << oneLogField(event.process.cmd.value)
                    << " " << owlsm::globals::g_kubernetes_client.describeLookupState(container_id));
            }
            pod_uid.reset();
        }
        else
        {
            pod_info = owlsm::globals::g_kubernetes_client.lookupPodInfo(*pod_uid);
            if (!pod_info.has_value() && shouldLogPodUidMiss(*pod_uid))
            {
                LOG_INFO("pod_uid_to_k8s_info miss pod_uid=" << *pod_uid
                    << " container_id=" << container_id
                    << " event=" << magic_enum::enum_name(event.type)
                    << " pid=" << event.process.pid
                    << " cmd=" << oneLogField(event.process.cmd.value));
            }
        }
    }

    build(kubernetes, owlsm::globals::g_kubernetes_client.nodeName(), container_id, pod_uid, pod_info);
}

bool KubernetesEventEnrichment::shouldLogMiss(const unsigned long long container_id) const
{
    const std::lock_guard lock(m_logged_miss_mutex);
    return m_logged_miss_container_ids.insert(container_id).second;
}

bool KubernetesEventEnrichment::shouldLogPodUidMiss(const std::string& pod_uid) const
{
    const std::lock_guard lock(m_logged_miss_mutex);
    return m_logged_miss_pod_uids.insert(pod_uid).second;
}

std::string KubernetesEventEnrichment::oneLogField(std::string value)
{
    for (char& character : value)
    {
        if (character == '\n' || character == '\r')
        {
            character = ' ';
        }
    }
    return value;
}

void KubernetesEventEnrichment::build(Kubernetes& kubernetes,
                                     const std::string& node_name,
                                     const unsigned long long container_id,
                                     const std::optional<std::string>& pod_uid,
                                     const std::optional<kubernetes::PodInfo>& pod_info)
{
    kubernetes = Kubernetes{};
    kubernetes.host_event = (container_id == 0);
    if (!node_name.empty())
    {
        kubernetes.node_name = node_name;
    }
    if (container_id != 0)
    {
        kubernetes.container_id = container_id;
    }
    if (pod_uid.has_value() && !pod_uid->empty())
    {
        kubernetes.pod_uid = *pod_uid;
        if (pod_info.has_value())
        {
            if (!pod_info->ns.empty())
            {
                kubernetes.pod_namespace = pod_info->ns;
            }
            if (!pod_info->name.empty())
            {
                kubernetes.pod_name = pod_info->name;
            }
            if (!pod_info->labels.empty())
            {
                kubernetes.pod_labels = pod_info->labels;
            }
        }
    }
}

}
