#include "logger.hpp"
#include "globals/global_numbers.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/async.h>
#include <spdlog/fmt/fmt.h>
#include <fstream>
#include <chrono>

namespace owlsm {

Logger& Logger::getInstance() 
{
    static Logger instance;
    return instance;
}

::spdlog::level::level_enum Logger::toSpdlogLevel(enum log_level level) 
{
    switch (level) 
    {
        case LOG_LEVEL_DEBUG:   return ::spdlog::level::debug;
        case LOG_LEVEL_INFO:    return ::spdlog::level::info;
        case LOG_LEVEL_WARNING: return ::spdlog::level::warn;
        case LOG_LEVEL_ERROR:   return ::spdlog::level::err;
        default:                return ::spdlog::level::info;
    }
}

void Logger::openLogger(const std::string& log_path, ::spdlog::level::level_enum level, bool async)
{
    if (async)
    {
        ::spdlog::init_thread_pool(8192, 1);
        m_logger = ::spdlog::create_async<::spdlog::sinks::rotating_file_sink_mt>(
            "owlsm_logger", log_path, 100 * owlsm::globals::MB, owlsm::globals::MAX_LOG_FILES);
        ::spdlog::flush_every(std::chrono::milliseconds(500));
    }
    else
    {
        m_logger = ::spdlog::rotating_logger_mt(
            "owlsm_logger", log_path, 100 * owlsm::globals::MB, owlsm::globals::MAX_LOG_FILES);
    }

    m_logger->set_pattern("[%d.%m.%Y %H:%M:%S.%e][%l]%v");
    m_logger->set_level(level);
    m_async = async;
    m_initialized = true;
}

void Logger::initialize(const std::string& log_path, enum log_level level, bool async) 
{
    Logger& instance = getInstance();
    
    if (instance.m_initialized) 
        return;

    try 
    {
        std::filesystem::path log_file_path(log_path);
        if (log_file_path.has_parent_path()) 
            std::filesystem::create_directories(log_file_path.parent_path());

        instance.openLogger(log_path, toSpdlogLevel(level), async);
    } 
    catch (const ::spdlog::spdlog_ex& ex) 
    {
        throw std::runtime_error("Logger initialization failed: " + std::string(ex.what()));
    }
}

void Logger::applyConfiguredLogLocation(const std::string& log_location)
{
    if (log_location.empty())
        return;

    Logger& instance = getInstance();

    if (!instance.m_initialized || !instance.m_logger)
        throw std::runtime_error("Logger not initialized! Call Logger::initialize() first.");

    auto* active_sink = static_cast<::spdlog::sinks::rotating_file_sink_mt*>(instance.m_logger->sinks()[0].get());
    const std::filesystem::path active_path = std::filesystem::absolute(active_sink->filename()).lexically_normal();
    const std::filesystem::path new_path = std::filesystem::absolute(log_location).lexically_normal();

    if (active_path == new_path)
        return;

    const auto saved_level = instance.m_logger->level();
    const bool saved_async = instance.m_async;

    instance.m_logger->flush();
    ::spdlog::drop("owlsm_logger");
    instance.m_logger.reset();
    instance.m_initialized = false;

    // For async loggers, spdlog::shutdown() blocks until the worker thread drains
    // all queued messages (including the flush above) to disk. Without this, the
    // file copy below might see an empty or incomplete file.
    if (saved_async)
        ::spdlog::shutdown();

    std::filesystem::create_directories(new_path.parent_path());

    if (std::filesystem::exists(active_path) && std::filesystem::file_size(active_path) > 0)
    {
        std::ifstream in(active_path, std::ios::binary);
        std::ofstream out(new_path, std::ios::binary | std::ios::app);
        out << in.rdbuf();
    }

    if (std::filesystem::exists(active_path))
        std::filesystem::remove(active_path);

    instance.openLogger(new_path.string(), saved_level, saved_async);
}

void Logger::log(enum log_level level, const char* file, int line, const char* function, const std::string& message) 
{
    if (!m_initialized || !m_logger) 
    {
        throw std::runtime_error("Logger not initialized! Call Logger::initialize() first.");
    }

    std::string formatted_msg = fmt::format("[{}:{}:{}] {}", file, function, line, message);

    switch (level) 
    {
        case LOG_LEVEL_DEBUG:   m_logger->debug(formatted_msg); break;
        case LOG_LEVEL_INFO:    m_logger->info(formatted_msg); break;
        case LOG_LEVEL_WARNING: m_logger->warn(formatted_msg); break;
        case LOG_LEVEL_ERROR:   m_logger->error(formatted_msg); break;
        default: break;
    }
}

void Logger::setLogLevel(enum log_level level) 
{
    if (!m_initialized || !m_logger) 
    {
        throw std::runtime_error("Logger not initialized! Call Logger::initialize() first.");
    }

    m_logger->set_level(toSpdlogLevel(level));
}

bool Logger::shouldLog(enum log_level level) const
{
    if (!m_initialized || !m_logger) 
    {
        return false;
    }
    return m_logger->should_log(toSpdlogLevel(level));
}

void Logger::shutdown() 
{
    Logger& instance = getInstance();
    if (instance.m_logger) 
    {
        instance.m_logger->flush();
        ::spdlog::drop("owlsm_logger");
        instance.m_logger.reset();
    }
    instance.m_initialized = false;
    ::spdlog::shutdown();
}

Logger::~Logger() 
{
    if (m_logger) 
    {
        m_logger->flush();
        m_logger.reset();
    }
}

}
