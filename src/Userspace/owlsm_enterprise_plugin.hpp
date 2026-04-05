#pragma once

#include <string>
#include <cstdint>

namespace owlsm
{

class OwlsmEnterprisePlugin
{
public:
    OwlsmEnterprisePlugin() = default;
    ~OwlsmEnterprisePlugin();
    OwlsmEnterprisePlugin(const OwlsmEnterprisePlugin&) = delete;
    OwlsmEnterprisePlugin(OwlsmEnterprisePlugin&&) = delete;
    OwlsmEnterprisePlugin& operator=(const OwlsmEnterprisePlugin&) = delete;
    OwlsmEnterprisePlugin& operator=(OwlsmEnterprisePlugin&&) = delete;

    void initialize();
    std::string decryptConfig(const std::string& content) const;

private:
    using DecryptConfigFn = int (*)(const uint8_t*, size_t, uint8_t*, size_t*);

    void* m_handle = nullptr;
    int m_api_version = 0;
    DecryptConfigFn m_decrypt_config = nullptr;
};

}
