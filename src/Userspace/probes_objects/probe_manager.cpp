#include "log_levels_enum.h"
#include "rodata_maps_related_structs.h"
#include "all_bpf.skel.h"

#include "globals/global_strings.hpp"
#include "bpf_header_includes.h"
#include "rules_managment/rules_into_bpf_maps.hpp"
#include "events_structs.h"
#include "probe_manager.hpp"
#include "globals/global_objects.hpp"
#include "ringbuffers_messages_handlers.hpp"
#include "system_setup.hpp"
#include "globals/global_numbers.hpp"

#include <stdexcept>

namespace owlsm
{

    void ProbeManager::bpfOpen(const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules) 
    {
        bpf_object_open_opts open_opts = {};
        open_opts.sz = sizeof(open_opts);
        open_opts.pin_root_path = globals::SYS_FS_BPF_OWLSM_PATH;
        m_skel = std::shared_ptr<all_bpf>(all_bpf__open_opts(&open_opts), 
                                          [](all_bpf* skel) { if(skel) all_bpf__destroy(skel); });
        if (!m_skel) 
        {
            throw std::runtime_error("failed to open skeleton. errno: " + std::to_string(errno));
        }

        RulesIntoBpfMaps rules_into_bpf_maps;
        rules_into_bpf_maps.create_rule_maps_from_organized_rules(organized_rules, 
                                                                   owlsm::globals::g_config.rules_config.id_to_string,
                                                                   owlsm::globals::g_config.rules_config.id_to_predicate,
                                                                   owlsm::globals::g_config.rules_config.id_to_ip);
        m_skel->rodata->log_level_to_print = owlsm::globals::g_config.kernel.log_level;
        m_skel->rodata->anti_tampering_signals_action = static_cast<int>(owlsm::globals::g_config.features.anti_tampering.events.signals);
        m_skel->rodata->anti_tampering_ptrace_action = static_cast<int>(owlsm::globals::g_config.features.anti_tampering.events.ptrace);

        for (auto& probe : m_probes) 
        {
            probe->setSkel(m_skel);
            probe->bpfOpen();
        }
    }

    void ProbeManager::bpfLoad(const std::vector<unsigned int>& excluded_pids, const std::vector<unsigned int>& protected_pids) 
    {
        int err = all_bpf__load(m_skel.get());
        if (err)
        {
            throw std::runtime_error("failed to load ebpf program. errno: " + std::to_string(err));
        }

        addProgramRelatedPids(excluded_pids);
        addProtectedPids(protected_pids);

        for (auto& probe : m_probes)
        {
            probe->bpfLoad();
        }
    }
    
    void ProbeManager::bpfAttach()
    {
        startRingbuffers();
        saveEbpfAttachTime();

        for (auto& probe : m_probes)
        {
            probe->bpfAttach();
        }

        LOG_INFO("Attached all probes");
    }

    void ProbeManager::bpfDetach()
    {
        all_bpf__detach(m_skel.get());
        for (auto& probe : m_probes)
        {
            probe->bpfDetach();
        }
    }

    void ProbeManager::bpfDestroy()
    {
        g_ringbuffers_messages_handlers.destroy();
        for (auto& probe : m_probes)
        {
            probe->bpfDestroy();
        }

        SystemSetup::cleanupOwlsmDirectory(true);
    }

    void ProbeManager::startRingbuffers()
    {
        auto event_ring_buffer_ptr = std::shared_ptr<ring_buffer>(
            ring_buffer__new(bpf_map__fd(m_skel->maps.rb), handle_event_callback, nullptr, nullptr),
            [](ring_buffer* rb) { if(rb) ring_buffer__free(rb); });
        if (!event_ring_buffer_ptr)
        {
            throw std::runtime_error("failed to create event ring buffer. errno: " + std::to_string(errno));
        }
        auto error_ring_buffer_ptr = std::shared_ptr<ring_buffer>(
            ring_buffer__new(bpf_map__fd(m_skel->maps.errors), handle_error_callback, nullptr, nullptr),
            [](ring_buffer* rb) { if(rb) ring_buffer__free(rb); });
        if (!error_ring_buffer_ptr)
        {
            throw std::runtime_error("failed to create error ring buffer. errno: " + std::to_string(errno));
        }
        g_ringbuffers_messages_handlers.start(event_ring_buffer_ptr, error_ring_buffer_ptr);
    }

    void ProbeManager::saveEbpfAttachTime()
    {
        struct timespec ts;
        if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        {
            throw std::runtime_error("clock_gettime. errno " + std::to_string(errno));
        }
        unsigned long long prog_start_ns = (unsigned long long)ts.tv_sec * globals::NANOSECONDS_IN_SECOND + ts.tv_nsec;

        unsigned int key = 0;
        int map_fd = bpf_map__fd(m_skel->maps.ebpf_program_start_time);
        if (bpf_map_update_elem(map_fd, &key, &prog_start_ns, BPF_ANY) < 0)
        {
            throw std::runtime_error("save_ebpf_attach_time: bpf_map_update_elem");
        }

        if (bpf_map_freeze(map_fd) < 0)
        {
            throw std::runtime_error("bpf_map_freeze (BPF_MAP_FREEZE)");
        }
    }
    
    void ProbeManager::addProgramRelatedPids(const std::vector<unsigned int>& excluded_pids)
    {
        int map_fd = bpf_map__fd(m_skel->maps.program_related_pids);
        int dummy = 1;
        for(unsigned int pid : excluded_pids)
        {
            if (bpf_map_update_elem(map_fd, &pid, &dummy, BPF_ANY) < 0)
            {
                throw std::runtime_error("bpf_map_update_elem program_related_pids. pid: " + std::to_string(pid) + " errno: " + std::to_string(errno));
            }
        }
    }

    void ProbeManager::addProtectedPids(const std::vector<unsigned int>& protected_pids)
    {
        int map_fd = bpf_map__fd(m_skel->maps.protected_processes);
        int dummy = 1;
        for (unsigned int pid : protected_pids)
        {
            if (bpf_map_update_elem(map_fd, &pid, &dummy, BPF_ANY) < 0)
            {
                throw std::runtime_error("bpf_map_update_elem protected_processes. pid: " + std::to_string(pid) + " errno: " + std::to_string(errno));
            }
        }
    }

    void ProbeManager::addAndAttachProbe(std::shared_ptr<AbstractProbe> probe)
    {
        probe->setSkel(m_skel);
        probe->bpfOpen();
        probe->bpfLoad();
        probe->bpfAttach();
        std::lock_guard<std::mutex> lock(m_probes_mutex);
        m_probes.push_back(std::move(probe));
    }
}