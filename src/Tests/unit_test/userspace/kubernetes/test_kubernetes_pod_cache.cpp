#include <gtest/gtest.h>
#include "kubernetes/kubernetes_pod_cache.hpp"

#include <string>
#include <vector>

namespace
{

owlsm::kubernetes::PodInfo makePod(const std::string& uid,
                                   const std::string& name,
                                   const std::vector<std::string>& container_ids)
{
    owlsm::kubernetes::PodInfo info;
    info.uid = uid;
    info.name = name;
    info.ns = "default";
    info.container_ids = container_ids;
    return info;
}

}

class PodIdentityCacheTest : public ::testing::Test
{
protected:
    owlsm::kubernetes::PodIdentityCache m_cache;
};

TEST_F(PodIdentityCacheTest, upsert_and_lookup_by_uid_and_container_id)
{
    m_cache.upsert(makePod("pod-1", "nginx", {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }));

    const auto by_uid = m_cache.lookupByPodUid("pod-1");
    ASSERT_TRUE(by_uid.has_value());
    EXPECT_EQ(by_uid->name, "nginx");

    const auto by_container = m_cache.lookupByContainerId(
        "containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(by_container.has_value());
    EXPECT_EQ(by_container->uid, "pod-1");
    EXPECT_EQ(m_cache.livePodCount(), 1u);
}

TEST_F(PodIdentityCacheTest, upsert_replaces_old_container_ids)
{
    m_cache.upsert(makePod("pod-1", "nginx", {"id-a"}));
    m_cache.upsert(makePod("pod-1", "nginx", {"id-b"}));

    EXPECT_FALSE(m_cache.lookupByContainerId("id-a").has_value());
    ASSERT_TRUE(m_cache.lookupByContainerId("id-b").has_value());
}

TEST_F(PodIdentityCacheTest, delete_moves_pod_to_dead_lru)
{
    m_cache.upsert(makePod("pod-1", "nginx", {"id-a"}));
    m_cache.eraseByUid("pod-1");

    EXPECT_EQ(m_cache.livePodCount(), 0u);
    const auto by_uid = m_cache.lookupByPodUid("pod-1");
    ASSERT_TRUE(by_uid.has_value());
    EXPECT_EQ(by_uid->name, "nginx");
    const auto by_container = m_cache.lookupByContainerId("id-a");
    ASSERT_TRUE(by_container.has_value());
    EXPECT_EQ(by_container->uid, "pod-1");
}

TEST_F(PodIdentityCacheTest, dead_lru_keeps_only_ten_pods)
{
    for (int i = 0; i < 12; ++i)
    {
        const std::string uid = "pod-" + std::to_string(i);
        m_cache.upsert(makePod(uid, uid, {"id-" + std::to_string(i)}));
        m_cache.eraseByUid(uid);
    }

    EXPECT_FALSE(m_cache.lookupByPodUid("pod-0").has_value());
    EXPECT_FALSE(m_cache.lookupByPodUid("pod-1").has_value());
    EXPECT_TRUE(m_cache.lookupByPodUid("pod-2").has_value());
    EXPECT_TRUE(m_cache.lookupByPodUid("pod-11").has_value());
}

TEST_F(PodIdentityCacheTest, live_upsert_removes_uid_from_dead_lru)
{
    m_cache.upsert(makePod("pod-1", "old", {"id-a"}));
    m_cache.eraseByUid("pod-1");
    m_cache.upsert(makePod("pod-1", "new", {"id-b"}));

    const auto live = m_cache.lookupByPodUid("pod-1");
    ASSERT_TRUE(live.has_value());
    EXPECT_EQ(live->name, "new");
    EXPECT_EQ(m_cache.livePodCount(), 1u);
    EXPECT_FALSE(m_cache.lookupByContainerId("id-a").has_value());
}
