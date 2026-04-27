#pragma once

#include <string>
#include <memory>
#include <sstream>
#include <filesystem>

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

} 

#define LOG_DEBUG(msg)    owlsm::LogStream(LOG_LEVEL_DEBUG,   __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_DEBUG)) << msg
#define LOG_INFO(msg)     owlsm::LogStream(LOG_LEVEL_INFO,    __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_INFO)) << msg
#define LOG_WARN(msg)     owlsm::LogStream(LOG_LEVEL_WARNING, __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_WARNING)) << msg
#define LOG_ERROR(msg)    owlsm::LogStream(LOG_LEVEL_ERROR,   __FILE_NAME__, __LINE__, __FUNCTION__, owlsm::Logger::getInstance().shouldLog(LOG_LEVEL_ERROR)) << msg
