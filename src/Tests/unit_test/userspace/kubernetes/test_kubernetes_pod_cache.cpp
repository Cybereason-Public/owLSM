#include <gtest/gtest.h>
#include "kubernetes/kubernetes_pod_cache.hpp"

#include <string>

namespace
{

owlsm::kubernetes::PodInfo makePod(const std::string& uid,
                                   const std::string& name,
                                   const std::string& ns = "default")
{
    owlsm::kubernetes::PodInfo info;
    info.uid = uid;
    info.name = name;
    info.ns = ns;
    info.labels.emplace("app", name);
    return info;
}

}

class PodIdentityCacheTest : public ::testing::Test
{
protected:
    owlsm::kubernetes::PodIdentityCache m_cache;
};

TEST_F(PodIdentityCacheTest, upsert_and_lookup_by_uid)
{
    m_cache.upsert(makePod("pod-1", "nginx", "kube-system"));

    const auto by_uid = m_cache.lookupByPodUid("pod-1");
    ASSERT_TRUE(by_uid.has_value());
    EXPECT_EQ(by_uid->uid, "pod-1");
    EXPECT_EQ(by_uid->name, "nginx");
    EXPECT_EQ(by_uid->ns, "kube-system");
    ASSERT_EQ(by_uid->labels.size(), 1u);
    EXPECT_EQ(by_uid->labels.at("app"), "nginx");
    EXPECT_EQ(m_cache.livePodCount(), 1u);
}

TEST_F(PodIdentityCacheTest, upsert_replaces_name_namespace_and_labels)
{
    m_cache.upsert(makePod("pod-1", "old"));
    auto updated = makePod("pod-1", "new", "prod");
    updated.labels.clear();
    updated.labels.emplace("tier", "frontend");
    m_cache.upsert(updated);

    const auto by_uid = m_cache.lookupByPodUid("pod-1");
    ASSERT_TRUE(by_uid.has_value());
    EXPECT_EQ(by_uid->name, "new");
    EXPECT_EQ(by_uid->ns, "prod");
    ASSERT_EQ(by_uid->labels.size(), 1u);
    EXPECT_EQ(by_uid->labels.at("tier"), "frontend");
    EXPECT_EQ(m_cache.livePodCount(), 1u);
}

TEST_F(PodIdentityCacheTest, delete_removes_pod)
{
    m_cache.upsert(makePod("pod-1", "nginx"));
    m_cache.eraseByUid("pod-1");

    EXPECT_EQ(m_cache.livePodCount(), 0u);
    EXPECT_FALSE(m_cache.lookupByPodUid("pod-1").has_value());
}

TEST_F(PodIdentityCacheTest, empty_uid_is_ignored)
{
    m_cache.upsert(makePod("", "nginx"));
    m_cache.eraseByUid("");

    EXPECT_EQ(m_cache.livePodCount(), 0u);
    EXPECT_FALSE(m_cache.lookupByPodUid("").has_value());
}

TEST_F(PodIdentityCacheTest, clear_empties_cache)
{
    m_cache.upsert(makePod("pod-1", "nginx"));
    m_cache.upsert(makePod("pod-2", "redis"));
    m_cache.clear();

    EXPECT_EQ(m_cache.livePodCount(), 0u);
    EXPECT_FALSE(m_cache.lookupByPodUid("pod-1").has_value());
    EXPECT_FALSE(m_cache.lookupByPodUid("pod-2").has_value());
}
