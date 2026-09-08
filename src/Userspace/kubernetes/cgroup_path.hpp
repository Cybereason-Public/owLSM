#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace owlsm::kubernetes
{

class CgroupPath
{
public:
    static std::optional<std::uint64_t> cgroupIdFromCriPath(const std::filesystem::path& host_root,
                                                            const std::string& raw_path);
    static void throwIfNotCgroupV2(const std::filesystem::path& proc_path);

private:
    static std::optional<std::filesystem::path> parseCgroupsPath(const std::string& raw_path);
    static std::optional<std::string> systemdExpandSlice(const std::string& slice);
    static std::filesystem::path joinHost(const std::filesystem::path& host_root,
                                          const std::filesystem::path& parsed);
    static std::filesystem::path maybeDescendSingleChild(const std::filesystem::path& path);
    static std::optional<std::uint64_t> inodeFromPath(const std::filesystem::path& path);
    static bool isCgroupV2Mount(const std::filesystem::path& path);
};

}
