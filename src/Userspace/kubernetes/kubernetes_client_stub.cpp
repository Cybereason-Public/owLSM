#pragma clang diagnostic ignored "-Wunused-private-field"

#include "kubernetes/kubernetes_client.hpp"

namespace owlsm::kubernetes
{

KubernetesClient::~KubernetesClient()
{
}

void KubernetesClient::initialize()
{
}

void KubernetesClient::startNri(const int)
{
}

void KubernetesClient::destroy()
{
}

bool KubernetesClient::isReady() const
{
    return false;
}

std::size_t KubernetesClient::cachedPodCount() const
{
    return 0;
}

std::string KubernetesClient::nodeName() const
{
    return {};
}

std::optional<std::string> KubernetesClient::lookupPodUid(const std::uint64_t) const
{
    return std::nullopt;
}

std::optional<PodInfo> KubernetesClient::lookupByPodUid(const std::string&) const
{
    return std::nullopt;
}

void KubernetesClient::handlePodUpsert(const owlsm_k8s_pod*)
{
}

void KubernetesClient::handlePodDelete(const char*)
{
}

void KubernetesClient::confirmCgroupV2()
{
}

std::string KubernetesClient::readNodeName() const
{
    return {};
}

int KubernetesClient::startClientGo(const std::string&) const
{
    return 0;
}

std::string KubernetesClient::describeInitFailure(const int) const
{
    return {};
}

PodInfo KubernetesClient::copyPod(const owlsm_k8s_pod&)
{
    return {};
}

}

extern "C" int owlsm_k8s_nri_start(owlsm_k8s_nri_upsert_fn,
                                   owlsm_k8s_nri_remove_fn,
                                   owlsm_k8s_nri_sync_done_fn,
                                   owlsm_k8s_nri_disconnected_fn)
{
    return -1;
}

extern "C" void owlsm_k8s_nri_stop(void)
{
}
