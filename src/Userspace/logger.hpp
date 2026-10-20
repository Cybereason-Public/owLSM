#pragma once

#include <string>
#include <memory>
#include <sstream>
#include <filesystem>
#include <atomic>
#include <chrono>

#include "log_levels_enum.h"

// Forward declaration for spdlog logger (to avoid including spdlog in header)
namespace spdlog {
    class logger;
    namespace level {
        enum level_enum : int;
    }
}


namespace owlsm {

class Logger {
public:
    static Logger& getInstance();
    static void initialize(const std::string& log_path, enum log_level level, bool async = true);
    static void applyConfiguredLogLocation(const std::string& log_location);
    static void shutdown();
    void log(enum log_level level, const char* file, int line, const char* function, const std::string& message);
    void setLogLevel(enum log_level level);
    bool shouldLog(enum log_level level) const;

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

private:
    Logger() = default;
    ~Logger();
    static ::spdlog::level::level_enum toSpdlogLevel(enum log_level level);
    void openLogger(const std::string& log_path, ::spdlog::level::level_enum level, bool async);
    static void namePeriodicFlushThread();

    std::shared_ptr<::spdlog::logger> m_logger;
    bool m_initialized = false;
    bool m_async = false;
};

class LogStream
{
public:
    LogStream(enum log_level level, const char* file, int line, const char* func, bool enabled)
        : m_level(level), m_file(file), m_line(line), m_func(func), m_enabled(enabled)
    {
    }

    ~LogStream()
    {
        if (m_enabled)
        {
            Logger::getInstance().log(m_level, m_file, m_line, m_func, m_stream.str());
        }
    }

    LogStream(const LogStream&) = delete;
    LogStream& operator=(const LogStream&) = delete;

    template<typename T>
    LogStream& operator<<(const T& value)
    {
        if (m_enabled)
        {
            m_stream << value;
        }
        return *this;
    }

private:
    enum log_level m_level;
    const char* m_file;
    int m_line;
    const char* m_func;
    bool m_enabled;
    std::ostringstream m_stream;
};

// Copied concept from Abseil LogEveryNSecState::ShouldLog
// It prefers speed over an exact rate: concurrent callers can occasionally log
// more often than the requested interval, or skip a turn.
class LogEveryNSecState
{
public:
    bool shouldLog(double seconds)
    {
        using ticks = std::chrono::steady_clock::duration::rep;
        const ticks now_ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        ticks next_ticks = m_next_ticks.load(std::memory_order_relaxed);
        const ticks interval_ticks = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(seconds)).count();

        do
        {
            if (now_ticks <= next_ticks)
            {
                return false;
            }
        } while (!m_next_ticks.compare_exchange_weak(
            next_ticks,
            now_ticks + interval_ticks,
            std::memory_order_relaxed,
            std::memory_order_relaxed));
        return true;
    }

private:
    static_assert(std::atomic<std::chrono::steady_clock::duration::rep>::is_always_lock_free);
    std::atomic<std::chrono::steady_clock::duration::rep> m_next_ticks{0};
};

} 

#define OWLSM_LOG_EVERY_N_SEC(seconds, log_call)                 \
    do                                                           \
    {                                                            \
        static owlsm::LogEveryNSecState log_every_n_sec_state;   \
        if (log_every_n_sec_state.shouldLog(seconds))            \
        {                                                        \
            log_call;                                            \
        }                                                        \
    } while (0)

#define LOG_DEBUG(msg)    owlsm::LogStream(LOG_LEVEL_DEBUG,   __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_DEBUG)) << msg
#define LOG_INFO(msg)     owlsm::LogStream(LOG_LEVEL_INFO,    __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_INFO)) << msg
#define LOG_WARN(msg)     owlsm::LogStream(LOG_LEVEL_WARNING, __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_WARNING)) << msg
#define LOG_ERROR(msg)    owlsm::LogStream(LOG_LEVEL_ERROR,   __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_ERROR)) << msg
#define LOG_DEBUG_EVERY_N_SEC(seconds, msg) OWLSM_LOG_EVERY_N_SEC(seconds, LOG_DEBUG(msg))
#define LOG_INFO_EVERY_N_SEC(seconds, msg)  OWLSM_LOG_EVERY_N_SEC(seconds, LOG_INFO(msg))
#define LOG_WARN_EVERY_N_SEC(seconds, msg)  OWLSM_LOG_EVERY_N_SEC(seconds, LOG_WARN(msg))
#define LOG_ERROR_EVERY_N_SEC(seconds, msg) OWLSM_LOG_EVERY_N_SEC(seconds, LOG_ERROR(msg))
