#pragma once

#include "rodata_maps_related_structs.h"
#include "probes_objects/probe_manager.hpp"

namespace owlsm
{
class CreateProbeObjects
{
public:
    static ProbeManager createProbeManager(const ebpf_features& features);

private:
    static std::vector<std::shared_ptr<AbstractProbe>> createProbes();
    static void removeUnavailableProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes,
                                        const ebpf_features& features);
    static void addBasicProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addFileMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addNetworkMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addShellCommandsMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addAntiTamperingProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
};
}
