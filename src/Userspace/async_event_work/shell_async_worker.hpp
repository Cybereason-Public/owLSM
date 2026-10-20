#pragma once

#include "base_async_worker.hpp"
#include "events/event.hpp"
#include "shell_detection/shell_binary_info.hpp"

#include <mutex>
#include <unordered_set>
#include <memory>

namespace owlsm::events
{

class ShellAsyncWorker : public BaseAsyncWorker<Event>
{
public:
    ShellAsyncWorker();
    ~ShellAsyncWorker() override = default;

    void distributeIfNeeded(std::shared_ptr<Event> event);

protected:
    void processItem(std::shared_ptr<Event>& item) override;

private:
    FileKey fileKeyFromEvent(const Event& event) const;
    bool isKnownShell(const FileKey& key) const;
    void rememberKnownShell(const FileKey& key);
    void forgetKnownShell(const FileKey& key);

    std::unordered_set<FileKey, FileKeyHash> m_non_shells_quick_cache; // data source is always the event
    std::unordered_set<FileKey, FileKeyHash> m_known_shells_quick_cache; // data source is always the event
    mutable std::mutex m_known_shells_mutex; // event consumer inserts, shell-async erases on failure

    friend class ShellAsyncWorkerTest;
};

}

