#pragma once

#include "logger.hpp"
#include "thread_name.hpp"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <memory>

namespace owlsm::events
{

template <typename WorkItem>
class BaseAsyncWorker
{
public:
    BaseAsyncWorker(std::string name) : m_name(name) {}

    virtual ~BaseAsyncWorker()
    {
        stop();
    }

    BaseAsyncWorker(const BaseAsyncWorker&) = delete;
    BaseAsyncWorker& operator=(const BaseAsyncWorker&) = delete;

    void start()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_running = true;
        }
        m_thread = std::thread(&BaseAsyncWorker::workerLoop, this);
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_running = false;
        }
        m_cv.notify_one();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    void enqueue(std::shared_ptr<WorkItem> item)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.size() >= m_max_queue_size)
            {
                LOG_WARN(m_name << " queue is full, dropping item");
            }
            m_queue.push(std::move(item));
        }
        m_cv.notify_one();
    }

protected:
    virtual void processItem(std::shared_ptr<WorkItem>& item) = 0;

    virtual void onThreadStart() 
    {
        LOG_INFO(m_name << " thread started");
        std::string shortName = m_name.substr(0, 15);
        ThreadName::setCurrent(shortName.c_str());
    }

    virtual void onThreadStop() 
    {
        LOG_INFO(m_name << " thread stopped");
    }

private:
    void workerLoop()
    {
        onThreadStart();

        while (true)
        {
            std::shared_ptr<WorkItem> item;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this]()
                {
                    return !m_running || !m_queue.empty();
                });

                if (!m_running)
                {
                    break;
                }

                if (!m_queue.empty())
                {
                    item = std::move(m_queue.front());
                    m_queue.pop();
                }
            }

            if (item)
            {
                processItem(item);
            }
        }

        onThreadStop();
    }

    std::string m_name;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::queue<std::shared_ptr<WorkItem>> m_queue;
    std::atomic<bool> m_running{false};
    size_t m_max_queue_size = 10000;
};

}