#include "posix_signal_handler.hpp"
#include "logger.hpp"

#include <csignal>

namespace owlsm
{

PosixSignalHandler* PosixSignalHandler::s_instance = nullptr;

PosixSignalHandler::PosixSignalHandler()
    : m_exit_requested(false)
{
    s_instance = this;
    std::signal(SIGPIPE, signalHandler);
    std::signal(SIGUSR1, signalHandler);
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
}

void PosixSignalHandler::waitForExitSignal()
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_cv.wait(lock, [this]{ return m_exit_requested.load(); });
    LOG_INFO("Received exit signal, shutting down gracefully");
}

void PosixSignalHandler::signalHandler(int signal)
{
    if(!s_instance)
    {
        return;
    }
    
    if(signal == SIGPIPE)
    {
        LOG_INFO("Received SIGPIPE signal, ignoring");
    }
    else if(signal == SIGUSR1)
    {
        LOG_INFO("Received SIGUSR1 signal, ignoring");
    }
    else if(signal == SIGINT || signal == SIGTERM)
    {
        s_instance->m_exit_requested.store(true);
        s_instance->m_cv.notify_all();
    }
}

}

