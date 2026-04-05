#include "owlsm_enterprise_plugin.hpp"
#include "logger.hpp"
#include "globals/global_strings.hpp"

#include <dlfcn.h>
#include <filesystem>
#include <stdexcept>

namespace owlsm
{

void OwlsmEnterprisePlugin::initialize()
{
    if (!std::filesystem::exists(globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH))
    {
        return;
    }

    m_handle = dlopen(globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!m_handle)
    {
        throw std::runtime_error("Failed to load " + globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH + ": " + dlerror());
    }
    LOG_INFO("Loaded " << globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH);

    m_decrypt_config = reinterpret_cast<DecryptConfigFn>(dlsym(m_handle, "decrypt_config"));
    if (!m_decrypt_config)
    {
        throw std::runtime_error("Failed to import decrypt_config from " + globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH + ": " + dlerror());
    }

    const int* api_version_ptr = reinterpret_cast<const int*>(dlsym(m_handle, "owlsm_plugin_api_version"));
    if (!api_version_ptr)
    {
        throw std::runtime_error("Failed to import owlsm_plugin_api_version from " + globals::OWLSM_ENTERPRISE_PLUGIN_SO_PATH + ": " + dlerror());
    }
    m_api_version = *api_version_ptr;
    LOG_DEBUG("owlsm_enterprise_plugin API version: " << m_api_version);
}

std::string OwlsmEnterprisePlugin::decryptConfig(const std::string& content) const
{
    if (!m_decrypt_config)
    {
        return content;
    }

    size_t out_len = 0;
    m_decrypt_config(reinterpret_cast<const uint8_t*>(content.data()), content.size(), nullptr, &out_len);

    std::string decrypted(out_len, '\0');
    const int result = m_decrypt_config(reinterpret_cast<const uint8_t*>(content.data()), content.size(),
        reinterpret_cast<uint8_t*>(decrypted.data()), &out_len);

    if (result != 0)
    {
        throw std::runtime_error("decrypt_config failed");
    }

    decrypted.resize(out_len);
    return decrypted;
}

OwlsmEnterprisePlugin::~OwlsmEnterprisePlugin()
{
    if (m_handle)
    {
        dlclose(m_handle);
    }
    m_handle = nullptr;
    m_api_version = 0;
    m_decrypt_config = nullptr;
}

}
