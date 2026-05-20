#pragma once

#include "probes_objects/probe_manager.hpp"

namespace owlsm
{
class CreateProbeObjects
{
public:
    static ProbeManager createProbeManager();

private:
    static std::vector<std::shared_ptr<AbstractProbe>> createProbes();
    static void addBasicProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addFileMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addNetworkMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addShellCommandsMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
    static void addAntiTamperingProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes);
};
}