#include "log_levels_enum.h"
#include "rodata_maps_related_structs.h"
#include "all_bpf.skel.h"
#include "probes_objects/lsm_probe.hpp"
#include "probes_objects/fentry_probe.hpp"
#include "probes_objects/tracepoint_probe.hpp"
#include "probes_objects/uprobe_probe.hpp"
#include "probes_objects/create_probe_objects.hpp"
#include "globals/global_objects.hpp"

namespace owlsm
{
    ProbeManager CreateProbeObjects::createProbeManager(const ebpf_features& features)
    {
        std::vector<std::shared_ptr<AbstractProbe>> probes = createProbes();
        removeUnavailableProbes(probes, features);
        return ProbeManager(std::move(probes), features);
    }

    std::vector<std::shared_ptr<AbstractProbe>> CreateProbeObjects::createProbes()
    {
        std::vector<std::shared_ptr<AbstractProbe>> probes;
        addBasicProbes(probes);
        addFileMonitoringProbes(probes);
        addNetworkMonitoringProbes(probes);
        addShellCommandsMonitoringProbes(probes);
        addAntiTamperingProbes(probes);
        return probes;
    }

    void CreateProbeObjects::removeUnavailableProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes,
                                                     const ebpf_features& features)
    {
        if (features.chown_hook_available)
        {
            return;
        }

        probes.erase(
            std::remove_if(probes.begin(), probes.end(),
                [](const std::shared_ptr<AbstractProbe>& probe) {
                    if (probe->getProbeType() != probe_type::LSM)
                    {
                        return false;
                    }

                    const auto lsm_probe = std::static_pointer_cast<LsmProbe>(probe);
                    return lsm_probe->getEventType() == CHOWN;
                }),
            probes.end());
    }

    void CreateProbeObjects::addBasicProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes)
    {
        probes.reserve(4);
        probes.push_back(std::make_shared<LsmProbe>(EXEC));
        probes.push_back(std::make_shared<FentryProbe>(FORK));
        probes.push_back(std::make_shared<FentryProbe>(EXIT));
        probes.push_back(std::make_shared<TracepointProbe>());
    }

    void CreateProbeObjects::addFileMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes)
    {
        if(owlsm::globals::g_config.features.file_monitoring.enabled)
        {
            if(owlsm::globals::g_config.features.file_monitoring.events.chmod) { probes.push_back(std::make_shared<LsmProbe>(CHMOD)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.chown) { probes.push_back(std::make_shared<LsmProbe>(CHOWN)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.file_create) { probes.push_back(std::make_shared<LsmProbe>(FILE_CREATE)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.unlink) { probes.push_back(std::make_shared<LsmProbe>(UNLINK)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.rename) { probes.push_back(std::make_shared<LsmProbe>(RENAME)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.write) { probes.push_back(std::make_shared<LsmProbe>(WRITE)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.read) { probes.push_back(std::make_shared<LsmProbe>(READ)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.mkdir) { probes.push_back(std::make_shared<LsmProbe>(MKDIR)); }
            if(owlsm::globals::g_config.features.file_monitoring.events.rmdir) { probes.push_back(std::make_shared<LsmProbe>(RMDIR)); }
        }

    }

    void CreateProbeObjects::addNetworkMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes)
    {
        if (owlsm::globals::g_config.features.network_monitoring.enabled)
        {
            probes.push_back(std::make_shared<LsmProbe>(NETWORK));
        }
    }

    void CreateProbeObjects::addShellCommandsMonitoringProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes)
    {
        if (!owlsm::globals::g_config.features.shell_commands_monitoring.enabled)
        {
            return;
        }

        const auto shells = owlsm::globals::g_shells_db.getAll();
        for (const auto& shell : shells)
        {
            probes.push_back(std::make_shared<UprobeProbe>(shell.path, shell.shell_type));
        }
    }

    void CreateProbeObjects::addAntiTamperingProbes(std::vector<std::shared_ptr<AbstractProbe>>& probes)
    {
        const auto& at = owlsm::globals::g_config.features.anti_tampering;
        if (!at.enabled)
        {
            return;
        }
        if (at.events.signals != EXCLUDE_EVENT)
        {
            probes.push_back(std::make_shared<LsmProbe>(SIGNAL));
        }
        if (at.events.ptrace != EXCLUDE_EVENT)
        {
            probes.push_back(std::make_shared<LsmProbe>(PTRACE));
        }
    }

}
