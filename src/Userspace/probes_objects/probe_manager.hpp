#pragma once

#include "rodata_maps_related_structs.h"
#include "probes_objects/abstract_probe.hpp"
#include "configuration/rule.hpp"
#include "events_structs.h"

#include <mutex>

namespace owlsm
{
class ProbeManager : public AbstractProbe
{
public:
    ProbeManager(std::vector<std::shared_ptr<AbstractProbe>>&& probes, const ebpf_features& features)
        : AbstractProbe(probe_type::PROBE_MANAGER), m_probes(std::move(probes)), m_ebpf_features(features) {}
    
    ProbeManager() : AbstractProbe(probe_type::PROBE_MANAGER) {}
    virtual ~ProbeManager() override = default;

    ProbeManager& operator=(const ProbeManager& other)
    {
        if (this != &other)
        {
            AbstractProbe::operator=(other);
            m_probes = other.m_probes;
            m_ebpf_features = other.m_ebpf_features;
        }
        return *this;
    }
    
    void bpfOpen(const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules);
    void bpfLoad(const std::vector<unsigned int>& excluded_pids, const std::vector<unsigned int>& protected_pids);
    virtual void bpfAttach() override;
    virtual void bpfDetach() override;
    virtual void bpfDestroy() override;
    void addAndAttachProbe(std::shared_ptr<AbstractProbe> probe);

private:
    void startRingbuffers();
    void saveEbpfAttachTime();
    void addProgramRelatedPids(const std::vector<unsigned int>& excluded_pids);
    void addProtectedPids(const std::vector<unsigned int>& protected_pids);
    void disableUnavailableProbes();

    using AbstractProbe::bpfOpen;
    using AbstractProbe::bpfLoad;

    std::vector<std::shared_ptr<AbstractProbe>> m_probes;
    std::mutex m_probes_mutex;
    ebpf_features m_ebpf_features{};
};
}
