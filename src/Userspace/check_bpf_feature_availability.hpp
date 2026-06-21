#pragma once

#include "rodata_maps_related_structs.h"
#include "features_test.skel.h"

namespace owlsm
{

class CheckBpfFeatureAvailability
{
public:
    CheckBpfFeatureAvailability();

    const ebpf_features& getFeatures() const { return m_features; }

private:
    bool probeChownHook();
    bool probeRingbufferMapValue();
    void setOnlyAutoload(features_test_bpf* skel, bpf_program* target);

    ebpf_features m_features{};
};

}
