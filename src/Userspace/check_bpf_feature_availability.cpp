#include "check_bpf_feature_availability.hpp"
#include "features_test.skel.h"
#include "logger.hpp"
#include "globals/global_strings.hpp"
#include "syscall_tracepoint_layout.h"

#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <string>
#include <fstream>
#include <filesystem>
#include <system_error>

namespace owlsm
{

CheckBpfFeatureAvailability::CheckBpfFeatureAvailability()
{
    m_features.chown_hook_available = probeChownHook();
    if (!m_features.chown_hook_available)
    {
        LOG_WARN("lsm/path_chown is not supported on this kernel; chown monitoring disabled");
    }

    m_features.ringbuffer_map_value_available = probeRingbufferMapValue();
}

bool CheckBpfFeatureAvailability::probeChownHook()
{
    features_test_bpf* skel = features_test_bpf__open();
    if (!skel)
    {
        return false;
    }

    setOnlyAutoload(skel, skel->progs.probe_path_chown);
    const int err = features_test_bpf__load(skel);
    features_test_bpf__destroy(skel);
    if (err != 0)
    {
        LOG_DEBUG("chown hook feature probe failed to load: " << std::strerror(-err));
        return false;
    }

    return true;
}

bool CheckBpfFeatureAvailability::probeRingbufferMapValue()
{
    features_test_bpf* skel = features_test_bpf__open();
    if (!skel)
    {
        return false;
    }

    setOnlyAutoload(skel, skel->progs.probe_path_chmod);
    const int err = features_test_bpf__load(skel);
    features_test_bpf__destroy(skel);
    if (err != 0)
    {
        LOG_DEBUG("ringbuffer map value feature probe failed to load: " << std::strerror(-err));
        return false;
    }

    return true;
}

void CheckBpfFeatureAvailability::setOnlyAutoload(features_test_bpf* skel, bpf_program* target)
{
    bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, skel->obj)
    {
        bpf_program__set_autoload(prog, prog == target);
    }
}

void CheckBpfFeatureAvailability::validateExecArgvOffsets()
{
    const std::string syscalls_dir = globals::TRACE_FS_SYSCALLS_DIR;
    validateArgvOffset(syscalls_dir + "/sys_enter_execve/format",   SYS_ENTER_EXECVE_ARGV_OFFSET);
    validateArgvOffset(syscalls_dir + "/sys_enter_execveat/format", SYS_ENTER_EXECVEAT_ARGV_OFFSET);
}

bool CheckBpfFeatureAvailability::validateArgvOffset(const std::string& format_path, int expected_offset)
{
    std::error_code ec;
    if (!std::filesystem::exists(format_path, ec))
    {
        LOG_WARN("Tracepoint format file not found: " << format_path << "; skipping exec argv offset validation.");
        return false;
    }

    const int argv_offset = parseTracepointFieldOffset(format_path, "argv");
    if (argv_offset < 0)
    {
        LOG_WARN("Could not parse the 'argv' offset from " << format_path << "; skipping exec argv offset validation.");
        return false;
    }

    if (argv_offset != expected_offset)
    {
        LOG_ERROR("Tracepoint " << format_path << " 'argv' is at offset " << argv_offset 
            << " on this kernel, but owLSM was built for offset " << expected_offset);
        return false;
    }
    return true;
}

int CheckBpfFeatureAvailability::parseTracepointFieldOffset(const std::string& format_path, const std::string& field_name)
{
    std::ifstream file(format_path);
    if (!file)
    {
        return -1;
    }

    const std::string field_token = " " + field_name + ";";
    const std::string offset_key  = "offset:";
    std::string line;
    while (std::getline(file, line))
    {
        if (line.find(field_token) == std::string::npos)
        {
            continue;
        }
        const auto pos = line.find(offset_key);
        if (pos == std::string::npos)
        {
            return -1;
        }
        return static_cast<int>(std::strtol(line.c_str() + pos + offset_key.size(), nullptr, 10));
    }
    return -1;
}

}
