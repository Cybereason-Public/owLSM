#pragma once

#include "globals/global_numbers.hpp"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>

namespace owlsm::kubernetes
{

class ContainerId
{
public:
    static std::string stripRuntimePrefix(const std::string& container_id)
    {
        const auto separator = container_id.find("://");
        if (separator == std::string::npos)
        {
            return container_id;
        }
        return container_id.substr(separator + 3);
    }

    static std::optional<std::uint64_t> toU64(const std::string& container_id)
    {
        const auto stripped = stripRuntimePrefix(container_id);
        if (stripped.size() < owlsm::globals::CONTAINER_ID_U64_HEX_LENGTH)
        {
            return std::nullopt;
        }
        for (int i = 0; i < owlsm::globals::CONTAINER_ID_U64_HEX_LENGTH; ++i)
        {
            if (!std::isxdigit(static_cast<unsigned char>(stripped[i])))
            {
                return std::nullopt;
            }
        }
        return static_cast<std::uint64_t>(std::strtoull(
            stripped.substr(0, owlsm::globals::CONTAINER_ID_U64_HEX_LENGTH).c_str(), nullptr, 16));
    }
};

}
