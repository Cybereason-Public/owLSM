#pragma once

#include <string>

namespace owlsm::globals 
{
    constexpr const char* SYS_FS_BPF_PATH = "/sys/fs/bpf";
    constexpr const char* SYS_FS_BPF_OWLSM_PATH = "/sys/fs/bpf/owLSM";
    constexpr const char* UNIT_TEST_LOG_PATH = "/tmp/unit_test.log";
    constexpr const char* LOG_FILE_NAME = "owlsm.log";
    constexpr const char* DB_FILE_NAME = "owlsm.db";
    constexpr const char* RESOURCES_DIR_NAME = "resources";

    extern const std::string CURRENT_PROCESS_DIR;
    extern const std::string DB_PATH;
    extern const std::string OWLSM_ENTERPRISE_PLUGIN_SO_PATH;
}