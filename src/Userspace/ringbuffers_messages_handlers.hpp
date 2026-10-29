#pragma once

#include "bpf_header_includes.h"
#include "events/sync_enrichment.hpp"
#include "async_event_work/async_work_distributor.hpp"
#include "events/event_to_json.hpp"
#include "events/event_to_flatbuffer.hpp"
#include "logger.hpp"
#include "thread_name.hpp"
#include "profiler_stats.hpp"

#include "globals/global_objects.hpp"
#include "globals/global_numbers.hpp"

#include <cstddef>
#include <deque>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <string>
#include <chrono>
#include <algorithm>
#include <utility>
#include <unistd.h>

namespace owlsm
{

template <typename MessageType, typename SyncEnrichment, typename AsyncWorkDistributor>
class RingbufferMessagesHandler
{
    using RawType = typename MessageType::RawType;

public:
    RingbufferMessagesHandler(std::shared_ptr<struct ring_buffer>& ringbuffer, int output_fd,
        const char* poll_thread_name, const char* consume_thread_name)
        : m_ringbuffer(ringbuffer), m_output_fd(output_fd),
          m_poll_thread_name(poll_thread_name), m_consume_thread_name(consume_thread_name)
    {
        m_local_queue.reserve(LOCAL_QUEUE_MAX_SIZE);
    }

    void start()
    {
        m_running = true;
        m_poll_thread_done = false;
        m_polling_thread = std::thread(&RingbufferMessagesHandler::ringbufferWorker, this);
        m_processing_thread = std::thread(&RingbufferMessagesHandler::consumerWorker, this);
        LOG_INFO("RingbufferMessagesHandler started. Output fd: " << m_output_fd);
    }

    void destroy()
    {
        {
            std::lock_guard<std::mutex> lock(m_main_queue_mutex);
            m_running = false;
        }
        m_main_queue_cv.notify_one();
        if (m_polling_thread.joinable())
        {
            m_polling_thread.join();
        }
        if (m_processing_thread.joinable())
        {
            m_processing_thread.join();
        }
        m_ringbuffer.reset();
        LOG_INFO("RingbufferMessagesHandler stopped. Output fd: " << m_output_fd);
    }

    int eventReceivedCallback(void* ctx, void* data, size_t len)
    {
        if (!m_running)
        {
            return 0;
        }

        if (len < sizeof(RawType))
        {
            LOG_ERROR("Invalid event data length");
            return -1;
        }

        const auto* ev = static_cast<const RawType*>(data);
        if (!ev)
        {
            LOG_ERROR("Invalid event data");
            return -1;
        }

        m_local_queue.push_back(std::make_shared<MessageType>(*ev));
        if (m_local_queue.size() < LOCAL_QUEUE_MAX_SIZE)
        {
            return 0;
        }
        if (!flushLocalQueue())
        {
            return -1;
        }
        return 0;
    }

private:
    void ringbufferWorker()
    {
        ThreadName::setCurrent(m_poll_thread_name);

        while (m_running)
        {
            const int consumed = ring_buffer__consume(m_ringbuffer.get());
            if (!m_running)
            {
                break;
            }
            if (consumed < 0)
            {
                flushLocalQueue();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            if (consumed == 0)
            {
                if (flushLocalQueue())
                {
                    ring_buffer__poll(m_ringbuffer.get(), static_cast<int>(WAIT_TIME.count()));
                }
                else
                {
                    std::this_thread::sleep_for(WAIT_TIME);
                }
                continue;
            }
            std::this_thread::sleep_for(WAIT_TIME);
        }

        flushLocalQueue();
        m_poll_thread_done.store(true, std::memory_order_release);
    }

    bool flushLocalQueue()
    {
        if (m_local_queue.empty())
        {
            return true;
        }

        std::size_t dropped = 0;
        bool enqueued = false;
        {
            std::lock_guard<std::mutex> lock(m_main_queue_mutex);
            static const auto max_size = static_cast<std::size_t>(owlsm::globals::g_config.userspace.max_events_queue_size);
            const std::size_t room = m_main_queue.size() >= max_size ? 0 : max_size - m_main_queue.size();
            const std::size_t accepted = std::min(room, m_local_queue.size());
            for (std::size_t index = 0; index < accepted; ++index)
            {
                m_main_queue.push_back(std::move(m_local_queue[index]));
            }
            dropped = m_local_queue.size() - accepted;
            enqueued = accepted > 0;
        }
        m_local_queue.clear();

        if (enqueued)
        {
            m_main_queue_cv.notify_one();
        }

        if (dropped == 0)
        {
            return true;
        }

        owlsm::profiler::ProfilerStats::recordQueueFull(dropped);
        LOG_ERROR_EVERY_N_SEC(10, "Max events queue size reached");
        return false;
    }

    void consumerWorker()
    {
        ThreadName::setCurrent(m_consume_thread_name);

        std::unique_ptr<events::IEventParser<MessageType>> serializer;
        if (owlsm::globals::g_config.userspace.output_type == config::OutputType::FLATBUFFERS)
        {
            serializer = std::make_unique<events::EventToFlatbuffer<MessageType>>();
        }
        else
        {
            serializer = std::make_unique<events::EventToJson<MessageType>>();
        }

        while (m_running)
        {
            {
                std::unique_lock<std::mutex> lock(m_main_queue_mutex);
                m_main_queue_cv.wait(lock, [this]()
                {
                    return !m_running || !m_main_queue.empty();
                });
                if (m_main_queue.empty())
                {
                    break;
                }
                else
                {
                    m_thread_queue.swap(m_main_queue);
                }
            }


            convertToMessages();
            enrichMessages();
            serializer->buildOutputBuffer(m_messages_queue);
            writeAndRecord(serializer->data(), serializer->size());
            distributeMessages();
            m_messages_queue.clear();
            m_thread_queue.clear();
        }

        while (!m_poll_thread_done.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(WAIT_TIME);
        }

        {
            std::lock_guard<std::mutex> lock(m_main_queue_mutex);
            m_thread_queue.swap(m_main_queue);
        }

        if (!m_thread_queue.empty())
        {
            convertToMessages();
            enrichMessages();
            serializer->buildOutputBuffer(m_messages_queue);
            writeAndRecord(serializer->data(), serializer->size());
            distributeMessages();
            m_messages_queue.clear();
            m_thread_queue.clear();
        }
    }

    void convertToMessages()
    {
        m_messages_queue.clear();
        m_messages_queue.reserve(m_thread_queue.size());
        for (auto& message : m_thread_queue)
        {
            m_messages_queue.push_back(std::move(message));
        }
    }

    void enrichMessages()
    {
        for (auto& msg : m_messages_queue)
        {
            m_sync_enrichment.enrich(msg);
        }
    }

    void distributeMessages()
    {
        for (auto& msg : m_messages_queue)
        {
            m_async_work_distributor.distribute(msg);
        }
    }
    
    void writeAndRecord(const void* data, size_t size)
    {
        const unsigned long long event_count = m_messages_queue.size();
        if (efficientBulkWrite(data, size))
        {
            owlsm::profiler::ProfilerStats::recordWrittenEvents(event_count);
        }
        else
        {
            owlsm::profiler::ProfilerStats::recordFailedEvents(event_count);
        }
    }

    bool efficientBulkWrite(const void* data, size_t size)
    {
        auto* ptr = static_cast<const char*>(data);
        size_t remaining = size;

        while (remaining > 0)
        {
            ssize_t written = ::write(m_output_fd, ptr, remaining);
            if (written < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                LOG_ERROR("Failed to write to output file descriptor");
                return false;
            }
            ptr += written;
            remaining -= written;
        }
        return true;
    }

    std::shared_ptr<struct ring_buffer> m_ringbuffer;
    int m_output_fd;
    const char* m_poll_thread_name;
    const char* m_consume_thread_name;
    std::thread m_polling_thread;
    std::thread m_processing_thread;
    static constexpr std::size_t LOCAL_QUEUE_MAX_SIZE = 100;
    static constexpr std::chrono::microseconds WAIT_TIME{250};
    std::vector<std::shared_ptr<MessageType>> m_local_queue;
    std::deque<std::shared_ptr<MessageType>> m_main_queue;
    std::mutex m_main_queue_mutex;
    std::condition_variable m_main_queue_cv;
    std::deque<std::shared_ptr<MessageType>> m_thread_queue;
    std::vector<std::shared_ptr<MessageType>> m_messages_queue;
    SyncEnrichment m_sync_enrichment;
    AsyncWorkDistributor m_async_work_distributor;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_poll_thread_done{false};
};

class RingbuffersMessagesHandlers 
{
    using EventHandler = RingbufferMessagesHandler<events::Event, events::SyncEventEnrichment, events::AsyncEventWorkDistributor>;
    using ErrorHandler = RingbufferMessagesHandler<events::Error, events::SyncErrorEnrichment, events::AsyncErrorWorkDistributor>;

public:
    RingbuffersMessagesHandlers() = default;

    ~RingbuffersMessagesHandlers()
    {
        destroy();
    }

    RingbuffersMessagesHandlers(RingbuffersMessagesHandlers&&) = delete;
    RingbuffersMessagesHandlers& operator=(RingbuffersMessagesHandlers&&) = delete;
    RingbuffersMessagesHandlers(const RingbuffersMessagesHandlers&) = delete;
    RingbuffersMessagesHandlers& operator=(const RingbuffersMessagesHandlers&) = delete;

    void start(std::shared_ptr<struct ring_buffer>& event_ringbuffer, std::shared_ptr<struct ring_buffer>& error_ringbuffer);
    void destroy();
    int handle_event(void* ctx, void* data, size_t len);
    int handle_error(void* ctx, void* data, size_t len);

private:
    std::unique_ptr<EventHandler> m_event_handler = nullptr;
    std::unique_ptr<ErrorHandler> m_error_handler = nullptr;
};

extern RingbuffersMessagesHandlers g_ringbuffers_messages_handlers;
int handle_event_callback(void* ctx, void* data, size_t len);
int handle_error_callback(void* ctx, void* data, size_t len);

}