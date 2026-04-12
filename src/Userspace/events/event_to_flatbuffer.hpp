#pragma once

#include "events/IEvent_parser.hpp"
#include "events/event.hpp"
#include "events/flatbuffers/include/owlsm_events_generated.h"
#include "logger.hpp"

#include <flatbuffers/flatbuffers.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class EventToFlatbufferTest;

namespace owlsm::events
{

template <typename MessageType>
class EventToFlatbuffer : public IEventParser<MessageType>
{
public:
    EventToFlatbuffer();
    void buildOutputBuffer(const std::vector<std::shared_ptr<MessageType>>& messages) override;
    const void* data() const override;
    size_t size() const override;

private:
    static std::string ipv4ToString(uint32_t be_addr);
    static std::string ipv6ToString(const unsigned int bytes[4]);
    static fb::FileType toFbFileType(file_type ft);
    static fb::EventType toFbEventType(event_type et);
    static fb::Action toFbAction(rule_action a);
    static flatbuffers::Offset<fb::File> serializeFile(flatbuffers::FlatBufferBuilder& builder, const File& f);
    static flatbuffers::Offset<fb::Process> serializeProcess(flatbuffers::FlatBufferBuilder& builder, const Process& p);
    void serializeEvent(const Event& ev);
    void serializeError(const Error& err);
    void serializeMessage(const Event& ev);
    void serializeMessage(const Error& err);

    flatbuffers::FlatBufferBuilder m_builder;
    std::vector<uint8_t> m_bulk_buffer;

    friend class ::EventToFlatbufferTest;
};

}
