#pragma once

#include <gtest/gtest.h>
#include "globals/global_strings.hpp"
#include "log_levels_enum.h"
#include "shared_unit_tests_structs_definitions.h"
#include "rodata_maps_related_structs.h"
#include "system_setup.hpp"
#include "ebpf_unit_tests.skel.h"

class BpfTestBase : public ::testing::Test
{
protected:
    // One load for the whole suite. Reloading verifies every program again (~1s per test).
    static void SetUpTestSuite();
    static void TearDownTestSuite();
    void SetUp() override;

    ebpf_unit_tests* skel = nullptr;

private:
    static ebpf_unit_tests* loadSkeleton();
    static void resetMaps(ebpf_unit_tests* skeleton);
    static bool shouldResetMap(const struct bpf_map* map);
    static void resetMap(struct bpf_map* map);
    static void deleteAllKeys(int fd, __u32 key_size);
    static bool zeroAllEntries(struct bpf_map* map);
    static bool isPerCpuMap(enum bpf_map_type type);

    static ebpf_unit_tests* m_shared_skel;
};
