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
    : BaseAsyncWorker<Event>("shell-async")
{
}

void ShellAsyncWorker::distributeIfNeeded(std::shared_ptr<Event> event)
{
    const FileKey key = fileKeyFromEvent(*event);

    if (m_non_shells_quick_cache.contains(key) || isKnownShell(key))
    {
        return;
    }

    if (ShellBinaryInfoExtractor::getShellType(event->process.file.path.value) == ShellType::UNKNOWN)
    {
        m_non_shells_quick_cache.insert(key);
        return;
    }

    rememberKnownShell(key);
    enqueue(std::move(event));
}

void ShellAsyncWorker::processItem(std::shared_ptr<Event>& item)
{
    const FileKey key = fileKeyFromEvent(*item);
    const std::string& shell_path = item->process.file.path.value;

    const auto shell_info = ShellBinaryInfoExtractor::getShellInfo(shell_path);
    if (!shell_info.has_value())
    {
        forgetKnownShell(key);
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
        forgetKnownShell(key);
        LOG_ERROR("Failed to add shell to DB: " << shell_path);
        return;
    }

    LOG_INFO("Discovered new shell at runtime: " << shell_path << " type: " << shellTypeToString(shell_info->shell_type));

    auto uprobe = std::make_shared<UprobeProbe>(shell_path, shell_info->shell_type);
    owlsm::globals::g_probe_manager.addAndAttachProbe(uprobe);
}

FileKey ShellAsyncWorker::fileKeyFromEvent(const Event& event) const
{
    const auto& process_file = event.process.file;
    return FileKey{process_file.inode, process_file.dev, process_file.last_modified_seconds};
}

bool ShellAsyncWorker::isKnownShell(const FileKey& key) const
{
    std::lock_guard<std::mutex> lock(m_known_shells_mutex);
    return m_known_shells_quick_cache.contains(key);
}

void ShellAsyncWorker::rememberKnownShell(const FileKey& key)
{
    std::lock_guard<std::mutex> lock(m_known_shells_mutex);
    m_known_shells_quick_cache.insert(key);
}

void ShellAsyncWorker::forgetKnownShell(const FileKey& key)
{
    std::lock_guard<std::mutex> lock(m_known_shells_mutex);
    m_known_shells_quick_cache.erase(key);
}

}

