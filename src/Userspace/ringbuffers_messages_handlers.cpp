#include "ringbuffers_messages_handlers.hpp"

namespace owlsm
{
    void RingbuffersMessagesHandlers::start(std::shared_ptr<struct ring_buffer>& event_ringbuffer, std::shared_ptr<struct ring_buffer>& error_ringbuffer)
    {
        m_event_handler = std::make_unique<EventHandler>(
            event_ringbuffer, STDOUT_FILENO, "event-poll", "event-consume");
        m_error_handler = std::make_unique<ErrorHandler>(
            error_ringbuffer, STDERR_FILENO, "error-poll", "error-consume");
        m_event_handler->start();
        m_error_handler->start();
    }

    void RingbuffersMessagesHandlers::destroy()
    {
        if(m_event_handler)
        {
            m_event_handler->destroy();
            m_event_handler = nullptr;
        }
        if(m_error_handler)
        {
            m_error_handler->destroy();
            m_error_handler = nullptr;
        }
    }

    int RingbuffersMessagesHandlers::handle_event(void* ctx, void* data, size_t len)
    {
        return m_event_handler->eventReceivedCallback(ctx, data, len);
    }

    int RingbuffersMessagesHandlers::handle_error(void* ctx, void* data, size_t len)
    {
        return m_error_handler->eventReceivedCallback(ctx, data, len);
    }

    int handle_event_callback(void* ctx, void* data, size_t len)
    {
        return g_ringbuffers_messages_handlers.handle_event(ctx, data, len);
    }

    int handle_error_callback(void* ctx, void* data, size_t len)
    {
        return g_ringbuffers_messages_handlers.handle_error(ctx, data, len);
    }

    RingbuffersMessagesHandlers g_ringbuffers_messages_handlers {};
}