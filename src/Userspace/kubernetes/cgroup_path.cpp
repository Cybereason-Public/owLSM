#include "kubernetes/cgroup_path.hpp"

#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include <stdexcept>
#include <string_view>
#include <system_error>

namespace owlsm::kubernetes
{

std::optional<std::uint64_t> CgroupPath::cgroupIdFromCriPath(const std::filesystem::path& host_root,
                                                             const std::string& raw_path)
{
    if (host_root.empty() || raw_path.empty())
    {
        return std::nullopt;
    }

    const auto parsed = parseCgroupsPath(raw_path);
    if (!parsed.has_value())
    {
        return std::nullopt;
    }

    const auto joined = maybeDescendSingleChild(joinHost(host_root, *parsed));
    return inodeFromPath(joined);
}

void CgroupPath::throwIfNotCgroupV2(const std::filesystem::path& proc_path)
{
    const auto path = proc_path / "1" / "root" / "sys" / "fs" / "cgroup";
    if (!isCgroupV2Mount(path))
    {
        throw std::runtime_error("host is not cgroup v2 (required in kubernetes mode)");
    }
}

std::optional<std::filesystem::path> CgroupPath::parseCgroupsPath(const std::string& raw_path)
{
    if (raw_path.find('/') != std::string::npos)
    {
        return std::filesystem::path(raw_path);
    }

    const auto first = raw_path.find(':');
    const auto second = (first == std::string::npos) ? std::string::npos : raw_path.find(':', first + 1);
    if (first == std::string::npos || second == std::string::npos ||
        raw_path.find(':', second + 1) != std::string::npos)
    {
        return std::nullopt;
    }

    const auto slice = systemdExpandSlice(raw_path.substr(0, first));
    if (!slice.has_value())
    {
        return std::nullopt;
    }

    const auto scope = raw_path.substr(first + 1, second - first - 1);
    auto name = raw_path.substr(second + 1);
    if (!name.ends_with(".slice"))
    {
        name = scope + "-" + name + ".scope";
    }
    return std::filesystem::path(*slice) / name;
}

std::optional<std::string> CgroupPath::systemdExpandSlice(const std::string& slice)
{
    constexpr std::string_view suffix = ".slice";
    if (slice.size() < suffix.size() || !slice.ends_with(suffix) || slice.find('/') != std::string::npos)
    {
        return std::nullopt;
    }

    const auto slice_name = slice.substr(0, slice.size() - suffix.size());
    if (slice_name == "-")
    {
        return "/";
    }

    std::string path;
    std::string prefix;
    std::size_t start = 0;
    while (start <= slice_name.size())
    {
        const auto end = slice_name.find('-', start);
        const auto component = slice_name.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (component.empty())
        {
            return std::nullopt;
        }
        path += "/" + prefix + component + ".slice";
        prefix += component + "-";
        if (end == std::string::npos)
        {
            break;
        }
        start = end + 1;
    }
    return path;
}

std::filesystem::path CgroupPath::joinHost(const std::filesystem::path& host_root,
                                           const std::filesystem::path& parsed)
{
    if (parsed.is_absolute())
    {
        return host_root / parsed.relative_path();
    }
    return host_root / parsed;
}

std::filesystem::path CgroupPath::maybeDescendSingleChild(const std::filesystem::path& path)
{
    std::error_code error;
    if (!std::filesystem::is_directory(path, error))
    {
        return path;
    }

    std::filesystem::path child;
    int dir_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(path, error))
    {
        if (error)
        {
            return path;
        }
        if (!entry.is_directory())
        {
            continue;
        }
        ++dir_count;
        if (dir_count > 1)
        {
            return path;
        }
        child = entry.path();
    }
    return (dir_count == 1) ? child : path;
}

std::optional<std::uint64_t> CgroupPath::inodeFromPath(const std::filesystem::path& path)
{
    struct stat path_stat {};
    if (stat(path.c_str(), &path_stat) != 0)
    {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(path_stat.st_ino);
}

bool CgroupPath::isCgroupV2Mount(const std::filesystem::path& path)
{
    struct stat path_stat {};
    struct stat parent_stat {};
    if (lstat(path.c_str(), &path_stat) != 0 || lstat(path.parent_path().c_str(), &parent_stat) != 0)
    {
        return false;
    }
    if (path_stat.st_dev == parent_stat.st_dev)
    {
        return false;
    }

    struct statfs fs_stat {};
    if (statfs(path.c_str(), &fs_stat) != 0)
    {
        return false;
    }
    return fs_stat.f_type == CGROUP2_SUPER_MAGIC;
}

}
