#pragma once

#include "events/IEvent_parser.hpp"
#include "events/event.hpp"
#include "logger.hpp"

#include <3rd_party/nlohmann/json.hpp>
#include <3rd_party/magic_enum/magic_enum.hpp>

#include <exception>
#include <type_traits>

template <typename T>
constexpr std::string_view to_string(T e) noexcept
{
    return magic_enum::enum_name(e);
}

namespace owlsm::events
{

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
            try
            {
                nlohmann::json j;
                if constexpr (std::is_same_v<MessageType, Event>)
                {
                    write_root_event_json(j, *msg);
                }
                else if constexpr (std::is_same_v<MessageType, Error>)
                {
                    write_root_error_json(j, *msg);
                }
                else
                {
                    static_assert(sizeof(MessageType) == 0, "EventToJson only supports Event and Error");
                }
                m_buffer += j.dump();
                m_buffer += '\n';
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Failed to serialize message to JSON: " << e.what());
            }
        }
    }

private:

    void write_root_event_json(nlohmann::json& j, const Event& ev);
    void write_root_error_json(nlohmann::json& j, const Error& e);
    std::string m_buffer;
};

} // namespace owlsm::events
