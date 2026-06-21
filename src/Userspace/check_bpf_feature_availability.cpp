#include "check_bpf_feature_availability.hpp"
#include "features_test.skel.h"
#include "logger.hpp"

#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>

namespace owlsm
{

CheckBpfFeatureAvailability::CheckBpfFeatureAvailability()
{
    m_features.chown_hook_available = probeChownHook();
    if (!m_features.chown_hook_available)
    {
        LOG_WARN("lsm/path_chown is not supported on this kernel; chown monitoring disabled");
    }

    m_features.ringbuffer_map_value_available = probeRingbufferMapValue();
}

bool CheckBpfFeatureAvailability::probeChownHook()
{
    features_test_bpf* skel = features_test_bpf__open();
    if (!skel)
    {
        return false;
    }

    setOnlyAutoload(skel, skel->progs.probe_path_chown);
    const int err = features_test_bpf__load(skel);
    features_test_bpf__destroy(skel);
    if (err != 0)
    {
        LOG_DEBUG("chown hook feature probe failed to load: " << std::strerror(-err));
        return false;
    }

    return true;
}

bool CheckBpfFeatureAvailability::probeRingbufferMapValue()
{
    features_test_bpf* skel = features_test_bpf__open();
    if (!skel)
    {
        return false;
    }

    setOnlyAutoload(skel, skel->progs.probe_path_chmod);
    const int err = features_test_bpf__load(skel);
    features_test_bpf__destroy(skel);
    if (err != 0)
    {
        LOG_DEBUG("ringbuffer map value feature probe failed to load: " << std::strerror(-err));
        return false;
    }

    return true;
}

void CheckBpfFeatureAvailability::setOnlyAutoload(features_test_bpf* skel, bpf_program* target)
{
    bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, skel->obj)
    {
        bpf_program__set_autoload(prog, prog == target);
    }
}

}
