#include "global_strings.hpp"

#include <filesystem>

namespace owlsm::globals 
{
    const std::string CURRENT_PROCESS_DIR = std::filesystem::canonical("/proc/self/exe").parent_path().string();
    const std::string DB_PATH = CURRENT_PROCESS_DIR + "/../" + RESOURCES_DIR_NAME + "/" + DB_FILE_NAME;
    const std::string OWLSM_ENTERPRISE_PLUGIN_SO_PATH = CURRENT_PROCESS_DIR + "/../lib/owlsm_enterprise_plugin.so";
}
