#pragma once

#include "events_structs.h"
#include "abstract_probe.hpp"

namespace owlsm
{
class LsmProbe : public AbstractProbe
{
public:
    LsmProbe(enum event_type event_type) 
        : AbstractProbe(probe_type::LSM), m_event_type(event_type) {}
    
    virtual ~LsmProbe() override = default;
    
    virtual void bpfOpen() override;
    virtual void bpfLoad() override;
    virtual void bpfAttach() override;

    event_type getEventType() const { return m_event_type; }

private:

    enum event_type m_event_type;
};
}
