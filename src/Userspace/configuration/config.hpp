#pragma once

#include <vector>

#include "log_levels_enum.h"
#include "rule.hpp"

namespace owlsm::config {

enum class OutputType 
{
    JSON,
    PROTOBUF,
    FLATBUFFERS
};

struct FileMonitoringEventsConfig 
{
    bool chmod = true;
    bool chown = true;
    bool file_create = true;
    bool unlink = true;
    bool rename = true;
    bool write = true;
    bool read = true;
    bool mkdir = true;
    bool rmdir = true;
};

struct FileMonitoringConfig 
{
    bool enabled = true;
    FileMonitoringEventsConfig events;
};

struct NetworkMonitoringConfig
{
    bool enabled = true;
};

struct ShellCommandsMonitoringConfig
{
    bool enabled = true;
};

struct FeaturesConfig 
{
    FileMonitoringConfig file_monitoring;
    NetworkMonitoringConfig network_monitoring;
    ShellCommandsMonitoringConfig shell_commands_monitoring;
};

struct UserspaceConfig 
{
    unsigned int max_events_queue_size = 10000;
    OutputType output_type = OutputType::JSON;
    log_level log_level = LOG_LEVEL_INFO;
    bool set_limits = true;
};

struct KernelConfig 
{
    log_level log_level = LOG_LEVEL_ERROR;
};

struct Config 
{
    FeaturesConfig features;
    UserspaceConfig userspace;
    KernelConfig kernel;
    RulesConfig rules_config;
};

}
