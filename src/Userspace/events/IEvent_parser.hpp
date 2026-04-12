#pragma once

#include "events/event.hpp"

#include <memory>
#include <vector>
#include <cstdint>

namespace owlsm::events
{

template <typename MessageType>
class IEventParser
{
public:
    virtual ~IEventParser() = default;

    virtual void buildOutputBuffer(const std::vector<std::shared_ptr<MessageType>>& messages) = 0;
    virtual const void* data() const = 0;
    virtual size_t size() const = 0;
};

}
