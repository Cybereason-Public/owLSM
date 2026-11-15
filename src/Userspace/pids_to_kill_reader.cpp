#include "pids_to_kill_reader.hpp"

#include "bpf_header_includes.h"
#include "events_structs.h"
#include "logger.hpp"
#include "thread_name.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace owlsm
{

PidsToKillReader::~PidsToKillReader()
{
    destroy();
}

void PidsToKillReader::start(int map_fd)
{
    if (map_fd < 0)
    {
        throw std::runtime_error("pids_to_kill map fd is invalid");
    }

    m_ringbuffer = std::shared_ptr<::ring_buffer>(
        ring_buffer__new(map_fd, &PidsToKillReader::onRecord, this, nullptr),
        [](::ring_buffer* rb) { if (rb) ring_buffer__free(rb); });
    if (!m_ringbuffer)
    {
        throw std::runtime_error("failed to create pids_to_kill ring buffer. errno: " + std::to_string(errno));
    }

    m_running.store(true);
    m_thread = std::thread(&PidsToKillReader::pollWorker, this);
    LOG_INFO("pids_to_kill reader started");
}

void PidsToKillReader::destroy()
{
    m_running.store(false);
    if (m_thread.joinable())
    {
        m_thread.join();
    }
    m_ringbuffer.reset();
}

void PidsToKillReader::pollWorker()
{
    ThreadName::setCurrent("pids-to-kill");

    while (m_running.load())
    {
        const int err = ring_buffer__poll(m_ringbuffer.get(), 1000);
        if (!m_running.load())
        {
            break;
        }
        if (err < 0)
        {
            LOG_ERROR("pids_to_kill poll failed. errno: " << -err);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

int PidsToKillReader::onRecord(void* ctx, void* data, std::size_t len)
{
    static_cast<PidsToKillReader*>(ctx)->handleRecord(data, len);
    return 0;
}

void PidsToKillReader::handleRecord(const void* data, std::size_t len) const
{
    if (data == nullptr || len < sizeof(pid_to_kill_t))
    {
        LOG_ERROR("invalid pids_to_kill record");
        return;
    }

    const auto* record = static_cast<const pid_to_kill_t*>(data);
    signalPid(record->pid);
}

void PidsToKillReader::signalPid(unsigned int pid) const
{
    if (pid <= 1)
    {
        LOG_ERROR("refusing to kill pid " << pid);
        return;
    }

    if (kill(static_cast<pid_t>(pid), SIGKILL) != 0 && errno != ESRCH)
    {
        LOG_ERROR("kill failed. pid: " << pid << " errno: " << errno);
    }
}

PidsToKillReader g_pids_to_kill_reader;

}
