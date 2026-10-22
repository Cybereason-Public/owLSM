#pragma once

#include "events/IEvent_parser.hpp"
#include "events/event.hpp"

#include <3rd_party/magic_enum/magic_enum.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

struct yyjson_mut_doc;

template <typename T>
constexpr std::string_view to_string(T e) noexcept
{
    return magic_enum::enum_name(e);
}

namespace owlsm::events
{

class EventJsonWriter
{
public:
    EventJsonWriter();
    ~EventJsonWriter();

    EventJsonWriter(const EventJsonWriter&) = delete;
    EventJsonWriter& operator=(const EventJsonWriter&) = delete;

    void appendEvent(std::string& out, const Event& event);
    void appendError(std::string& out, const Error& error);

private:
    struct Shapes;

    bool writeLine(std::string& out, yyjson_mut_doc* doc);

    static constexpr size_t INITIAL_LINE_BYTES = 16 * 1024;
    static constexpr size_t MAX_LINE_BYTES = 8 * 1024 * 1024;
    static constexpr int MAX_WRITE_ATTEMPTS = 8;

    std::unique_ptr<Shapes> m_shapes;
    std::vector<char> m_line;
};

template <typename MessageType>
class EventToJson : public IEventParser<MessageType>
{
public:
    EventToJson()
    {
        m_buffer.reserve(1024 * 1024 * 5);
    }

    const void* data() const override { return m_buffer.data(); }
    size_t size() const override { return m_buffer.size(); }

    void buildOutputBuffer(const std::vector<std::shared_ptr<MessageType>>& messages) override
    {
        m_buffer.clear();
        for (const auto& msg : messages)
        {
            if constexpr (std::is_same_v<MessageType, Event>)
            {
                m_writer.appendEvent(m_buffer, *msg);
            }
            else if constexpr (std::is_same_v<MessageType, Error>)
            {
                m_writer.appendError(m_buffer, *msg);
            }
            else
            {
                static_assert(sizeof(MessageType) == 0, "EventToJson only supports Event and Error");
            }
        }
    }

private:
    std::string m_buffer;
    EventJsonWriter m_writer;
};

}
