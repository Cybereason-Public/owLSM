#include <gtest/gtest.h>
#include "kubernetes/container_id.hpp"

TEST(ContainerIdTest, strip_is_noop_without_prefix)
{
    EXPECT_EQ(owlsm::kubernetes::ContainerId::stripRuntimePrefix(
                  "a1b2c3d4e5f607181122334455667788"),
              "a1b2c3d4e5f607181122334455667788");
}

TEST(ContainerIdTest, strip_runtime_prefix)
{
    EXPECT_EQ(owlsm::kubernetes::ContainerId::stripRuntimePrefix(
                  "containerd://a1b2c3d4e5f607181122334455667788"),
              "a1b2c3d4e5f607181122334455667788");
    EXPECT_EQ(owlsm::kubernetes::ContainerId::stripRuntimePrefix(
                  "cri-o://ffffffffffffffffffffffffffffffff"),
              "ffffffffffffffffffffffffffffffff");
}

TEST(ContainerIdTest, first_16_hex_to_u64)
{
    const auto id = owlsm::kubernetes::ContainerId::toU64(
        "a1b2c3d4e5f60718112233445566778899aabbccddeeff00");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, 0xa1b2c3d4e5f60718ULL);
}

TEST(ContainerIdTest, strips_then_truncates)
{
    const auto id = owlsm::kubernetes::ContainerId::toU64(
        "containerd://a1b2c3d4e5f60718112233445566778899aabbccddeeff00");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, 0xa1b2c3d4e5f60718ULL);
}

TEST(ContainerIdTest, rejects_short_or_non_hex)
{
    EXPECT_FALSE(owlsm::kubernetes::ContainerId::toU64("abc").has_value());
    EXPECT_FALSE(owlsm::kubernetes::ContainerId::toU64("gggggggggggggggg").has_value());
    EXPECT_FALSE(owlsm::kubernetes::ContainerId::toU64("").has_value());
}
