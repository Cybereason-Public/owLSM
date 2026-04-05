#pragma once

#include "configuration/config.hpp"
#include "probes_objects/probe_manager.hpp"
#include "shell_detection/shells_db.hpp"
#include "owlsm_enterprise_plugin.hpp"

namespace owlsm::globals 
{
    extern config::Config g_config;
    extern ProbeManager g_probe_manager;
    extern ShellsDB g_shells_db;
    extern OwlsmEnterprisePlugin g_owlsm_enterprise_plugin;
}