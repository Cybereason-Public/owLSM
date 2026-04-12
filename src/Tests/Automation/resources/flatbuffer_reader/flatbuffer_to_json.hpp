#pragma once

#include "events/flatbuffers/include/owlsm_events_generated.h"

#include <3rd_party/nlohmann/json.hpp>

#include <string>

class FlatbufferToJson
{
public:
    static std::string jsonLineFromFlatbufferEvent(const owlsm::fb::Event* ev);
    static std::string jsonLineFromFlatbufferError(const owlsm::fb::Error* err);

private:
    using json = nlohmann::json;

    static std::string fbStr(const flatbuffers::String* s);
    static json ownerJson(const owlsm::fb::Owner* o);
    static json fileJson(const owlsm::fb::File* f);
    static json processJson(const owlsm::fb::Process* p);
    static json eventDataJson(const owlsm::fb::Event* ev);
};
