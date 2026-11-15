#pragma once

struct ring_buffer;

#include <atomic>
#include <cstddef>
#include <memory>
#include <thread>

namespace owlsm
{

class PidsToKillReader
{
public:
    ~PidsToKillReader();
    void start(int map_fd);
    void destroy();

private:
    void pollWorker();
    static int onRecord(void* ctx, void* data, std::size_t len);
    void handleRecord(const void* data, std::size_t len) const;
    void signalPid(unsigned int pid) const;

    std::shared_ptr<::ring_buffer> m_ringbuffer;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
};

extern PidsToKillReader g_pids_to_kill_reader;

}
