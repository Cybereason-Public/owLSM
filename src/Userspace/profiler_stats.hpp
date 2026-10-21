#pragma once

#ifdef PROFILER_BUILD
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <atomic>
#include <chrono>
#endif

namespace owlsm::profiler
{

class ProfilerStats
{
public:
    static void recordQueueFull()
    {
#ifdef PROFILER_BUILD
        m_queue_full_drops.fetch_add(1, std::memory_order_relaxed);
#endif
    }

    static void recordWrittenEvents(unsigned long long count)
    {
#ifdef PROFILER_BUILD
        m_successful_events_written.fetch_add(count, std::memory_order_relaxed);
#endif
    }

    static void recordFailedEvents(unsigned long long count)
    {
#ifdef PROFILER_BUILD
        m_failed_events_written.fetch_add(count, std::memory_order_relaxed);
#endif
    }

    static void logSummary()
    {
#ifdef PROFILER_BUILD
        const unsigned long long ring_buffer_alloc_failures = owlsm::globals::g_probe_manager.getRingBufferAllocFailures();
        const unsigned long long successful = m_successful_events_written.load();
        const double elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - m_start_time).count();
        const double events_per_second = elapsed_seconds > 0.0 ? successful / elapsed_seconds : 0.0;

        LOG_INFO(
            "Profiler stats: {"
            << "\"ring_buffer_alloc_failures\":" << ring_buffer_alloc_failures << ","
            << "\"queue_full_drops\":" << m_queue_full_drops.load() << ","
            << "\"successful_events_written\":" << successful << ","
            << "\"failed_events_written\":" << m_failed_events_written.load() << ","
            << "\"events_per_second\":" << events_per_second
            << "}"
        );
#endif
    }

private:
#ifdef PROFILER_BUILD
    static inline std::atomic<unsigned long long> m_queue_full_drops{0};
    static inline std::atomic<unsigned long long> m_successful_events_written{0};
    static inline std::atomic<unsigned long long> m_failed_events_written{0};
    static inline std::chrono::steady_clock::time_point m_start_time{std::chrono::steady_clock::now()};
#endif
};

}
