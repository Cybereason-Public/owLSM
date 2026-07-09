#pragma once

#include <string>

#include "rodata_maps_related_structs.h"
#include "features_test.skel.h"

class CheckBpfFeatureAvailabilityTest;

namespace owlsm
{

class CheckBpfFeatureAvailability
{
public:
    CheckBpfFeatureAvailability();

    const ebpf_features& getFeatures() const { return m_features; }
    static void validateExecArgvOffsets();

private:
    bool probeChownHook();
    bool probeRingbufferMapValue();
    void setOnlyAutoload(features_test_bpf* skel, bpf_program* target);
    static int parseTracepointFieldOffset(const std::string& format_path, const std::string& field_name);
    static bool validateArgvOffset(const std::string& format_path, int expected_offset);

    ebpf_features m_features{};

    friend class ::CheckBpfFeatureAvailabilityTest;
};

}
