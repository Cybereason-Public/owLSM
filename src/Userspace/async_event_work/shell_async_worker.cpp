#include "shell_async_worker.hpp"
#include "globals/global_objects.hpp"
#include "log_levels_enum.h"
#include "rodata_maps_related_structs.h"
#include "all_bpf.skel.h"
#include "probes_objects/uprobe_probe.hpp"
#include "shell_detection/shell_binary_info_extractor.hpp"

namespace owlsm::events
{

ShellAsyncWorker::ShellAsyncWorker()
    : BaseAsyncWorker<Event>("ShellAsyncWorker")
{
}

void ShellAsyncWorker::distributeIfNeeded(std::shared_ptr<Event> event)
{
    const auto& process_file = event->process.file;
    const FileKey key{process_file.inode, process_file.dev, process_file.last_modified_seconds};

    if (m_non_shells_quick_cache.contains(key))
    {
        return;
    }

    if (ShellBinaryInfoExtractor::getShellType(process_file.path.value) == ShellType::UNKNOWN)
    {
        m_non_shells_quick_cache.insert(key);
        return;
    }

    enqueue(std::move(event));
}

void ShellAsyncWorker::processItem(std::shared_ptr<Event>& item)
{
    const std::string& shell_path = item->process.file.path.value;
    
    const auto shell_info = ShellBinaryInfoExtractor::getShellInfo(shell_path);
    if (!shell_info.has_value())
    {
        LOG_WARN("Failed to get shell info for: " << shell_path);
        return;
    }

    if (owlsm::globals::g_shells_db.find(shell_info.value()))
    {
        LOG_DEBUG("Shell already in DB: " << shell_path);
        return;
    }

    if (!owlsm::globals::g_shells_db.set(shell_info.value()))
    {
        LOG_ERROR("Failed to add shell to DB: " << shell_path);
        return;
    }

    LOG_INFO("Discovered new shell at runtime: " << shell_path << " type: " << shellTypeToString(shell_info->shell_type));

    auto uprobe = std::make_shared<UprobeProbe>(shell_path, shell_info->shell_type);
    owlsm::globals::g_probe_manager.addAndAttachProbe(uprobe);
}

}

