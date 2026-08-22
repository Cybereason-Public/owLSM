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

std::optional<PodInfo> KubernetesClient::lookupByPodUid(const std::string&) const
{
    return std::nullopt;
}

std::optional<PodInfo> KubernetesClient::lookupByContainerId(const std::string&) const
{
    return std::nullopt;
}

void KubernetesClient::handlePodUpsert(const owlsm_k8s_pod*)
{
}

void KubernetesClient::handlePodDelete(const char*)
{
}

PodInfo KubernetesClient::copyPod(const owlsm_k8s_pod&)
{
    return {};
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

}
