#include "shell_binary_info_extractor.hpp"
#include "logger.hpp"
#include "globals/global_numbers.hpp"

#include <filesystem>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <elfutils/libdwelf.h>
#include <cstring>
#include <cerrno>

namespace owlsm
{

std::optional<ShellBinaryInfo> ShellBinaryInfoExtractor::getShellInfo(const std::string& path)
{
    ShellBinaryInfo info;
    info.path = path;

    if (!statxInfo(path, info))
    {
        return std::nullopt;
    }

    info.shell_type = getShellType(path);
    if (info.shell_type == ShellType::UNKNOWN)
    {
        return std::nullopt;
    }

    getBuildId(path, info);
    getOffsets(path, info);

    return info;
}

ShellType ShellBinaryInfoExtractor::getShellType(const std::string& path)
{
    if (!isBinary(path))
    {
        return ShellType::UNKNOWN;
    }

    const std::string filename = std::filesystem::path(path).filename().string();
    const auto& known_shells = getKnownShellNames();
    
    if (known_shells.find(filename) != known_shells.end())
    {
        return shellNameToType(filename);
    }

    return ShellType::UNKNOWN;
}

bool ShellBinaryInfoExtractor::statxInfo(const std::string& path, ShellBinaryInfo& info)
{
    struct statx stx = {};
    const int statx_result = static_cast<int>(
        syscall(SYS_statx, AT_FDCWD, path.c_str(), 0,
                STATX_INO | STATX_MTIME | STATX_TYPE | STATX_MODE, &stx));

    if (statx_result == 0)
    {
        if (!S_ISREG(stx.stx_mode))
        {
            return false;
        }

        info.inode = stx.stx_ino;
        info.dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
        info.last_modified_time = static_cast<unsigned long long>(stx.stx_mtime.tv_sec) * globals::NANOSECONDS_IN_SECOND +
                                  static_cast<unsigned long long>(stx.stx_mtime.tv_nsec);

        return true;
    }

    LOG_ERROR("statx failed for " << path << ": " << strerror(errno));
    return false;
}

bool ShellBinaryInfoExtractor::isBinary(const std::string& path)
{
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        return false;
    }

    unsigned char magic[4] = {0};
    const ssize_t bytes_read = read(fd, magic, sizeof(magic));
    close(fd);

    if (bytes_read < 4)
    {
        return false;
    }

    // ELF magic: 0x7f 'E' 'L' 'F'
    return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

bool ShellBinaryInfoExtractor::getBuildId(const std::string& path, ShellBinaryInfo& info)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        LOG_ERROR("ELF library initialization failed");
        return false;
    }

    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        LOG_ERROR("Failed to open " << path << ": " << strerror(errno));
        return false;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf)
    {
        close(fd);
        LOG_ERROR("elf_begin failed for " << path);
        return false;
    }

    const void* id = nullptr;
    const ssize_t len = dwelf_elf_gnu_build_id(elf, &id);
    
    if (len > 0)
    {
        const auto* p = static_cast<const unsigned char*>(id);
        info.build_id.clear();
        info.build_id.reserve(static_cast<size_t>(len) * 2);
        for (ssize_t i = 0; i < len; ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", p[i]);
            info.build_id += hex;
        }
    }

    elf_end(elf);
    close(fd);
    return len > 0;
}

bool ShellBinaryInfoExtractor::getOffsets(const std::string& path, ShellBinaryInfo& info)
{
    const auto func_names = getShellFunctionNames(info.shell_type);
    if (func_names.start_function.empty() || func_names.end_function.empty())
    {
        return false;
    }

    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        LOG_ERROR("ELF library initialization failed");
        return false;
    }

    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        LOG_ERROR("Failed to open " << path << ": " << strerror(errno));
        return false;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf)
    {
        close(fd);
        LOG_ERROR("elf_begin failed for " << path);
        return false;
    }

    Elf_Scn* scn = nullptr;
    bool found_start = false;
    bool found_end = false;

    while ((scn = elf_nextscn(elf, scn)) != nullptr && (!found_start || !found_end))
    {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == nullptr)
        {
            continue;
        }

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
        {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
        {
            continue;
        }

        const size_t num_symbols = shdr.sh_size / shdr.sh_entsize;

        for (size_t i = 0; i < num_symbols && (!found_start || !found_end); ++i)
        {
            GElf_Sym sym;
            if (gelf_getsym(data, static_cast<int>(i), &sym) == nullptr)
            {
                continue;
            }

            const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name)
            {
                continue;
            }

            if (!found_start && func_names.start_function == name)
            {
                info.shell_start_function_offset = sym.st_value;
                info.is_shell_start_function_symbol_present = true;
                found_start = true;
            }

            if (!found_end && func_names.end_function == name)
            {
                info.shell_end_function_offset = sym.st_value;
                info.is_shell_end_function_symbol_present = true;
                found_end = true;
            }
        }
    }

    elf_end(elf);
    close(fd);

    return found_start || found_end;
}

}

