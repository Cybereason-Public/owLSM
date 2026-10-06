#include <gtest/gtest.h>
#include "kubernetes/nri_container_cache.hpp"
#include "kubernetes/container_id.hpp"
#include "globals/global_strings.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>

class NriContainerCacheTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_root = std::filesystem::temp_directory_path() / "owlsm_nri_cache_test";
        std::filesystem::remove_all(m_root);
        std::filesystem::create_directories(m_root / "kubepods.slice" / "ctr.scope");
        m_cache.setHostRoot(m_root);
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_root, error);
    }

    static std::uint64_t inodeOf(const std::filesystem::path& path)
    {
        struct stat path_stat {};
        EXPECT_EQ(stat(path.c_str(), &path_stat), 0);
        return static_cast<std::uint64_t>(path_stat.st_ino);
    }

    container_id_t containerValue(const std::uint64_t container_id) const
    {
        const auto it = m_cache.m_container_id_to_cgroup_id.find(container_id);
        if (it == m_cache.m_container_id_to_cgroup_id.end())
        {
            throw std::out_of_range("container id");
        }
        return it->first;
    }

    owlsm::kubernetes::NriContainerCache m_cache;
    std::filesystem::path m_root;
};

TEST_F(NriContainerCacheTest, upsert_writes_both_cpp_maps)
{
    const auto cgroup_id = inodeOf(m_root / "kubepods.slice" / "ctr.scope");
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/ctr.scope",
                   "default");

    const auto truncated = owlsm::kubernetes::ContainerId::toU64(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(m_cache.lookupPodUid(*truncated).value_or(""), "pod-uid-1");
    EXPECT_EQ(m_cache.lookupCgroupId(*truncated).value_or(0), cgroup_id);
    EXPECT_EQ(containerValue(*truncated).id, *truncated);
    EXPECT_FALSE(containerValue(*truncated).is_owlsm_container);
    EXPECT_FALSE(containerValue(*truncated).is_kube_system);
    EXPECT_EQ(m_cache.size(), 1u);
}

TEST_F(NriContainerCacheTest, empty_path_is_skipped)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "",
                   "default");
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, missing_directory_is_skipped)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/missing.scope",
                   "default");
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, start_reuses_pending_path_after_stat_fails)
{
    const char* id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.upsert(id, "pod-uid-1", "kubepods.slice/late.scope", owlsm::globals::KUBE_SYSTEM_NAMESPACE);
    EXPECT_EQ(m_cache.size(), 0u);

    const auto leaf = m_root / "kubepods.slice" / "late.scope";
    std::filesystem::create_directories(leaf);
    m_cache.upsert(id, "", "", "");

    const auto truncated = owlsm::kubernetes::ContainerId::toU64(id);
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(m_cache.size(), 1u);
    EXPECT_EQ(m_cache.lookupPodUid(*truncated).value_or(""), "pod-uid-1");
    EXPECT_EQ(m_cache.lookupCgroupId(*truncated).value_or(0), inodeOf(leaf));
}

TEST_F(NriContainerCacheTest, remove_drops_cpp_rows)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/ctr.scope",
                   "default");
    m_cache.remove("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const auto truncated = owlsm::kubernetes::ContainerId::toU64(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(m_cache.lookupPodUid(*truncated).value_or(""), "pod-uid-1");
    EXPECT_FALSE(m_cache.lookupCgroupId(*truncated).has_value());
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, clear_empties_maps)
{
    const char* id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.upsert(id, "pod-uid-1", "kubepods.slice/ctr.scope", "default");
    m_cache.remove(id);
    m_cache.clear();
    const auto truncated = owlsm::kubernetes::ContainerId::toU64(id);
    ASSERT_TRUE(truncated.has_value());
    EXPECT_FALSE(m_cache.lookupPodUid(*truncated).has_value());
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, removed_pod_uid_lru_drops_the_oldest_entry)
{
    const char* oldest_id = "0000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.upsert(oldest_id, "pod-uid-oldest", "kubepods.slice/ctr.scope", "default");
    m_cache.remove(oldest_id);
    for (int index = 1; index <= 50; ++index)
    {
        std::string id = std::to_string(index);
        id.append(64 - id.size(), 'b');
        m_cache.upsert(id.c_str(), "pod-uid", "kubepods.slice/ctr.scope", "default");
        m_cache.remove(id.c_str());
    }
    const auto oldest = owlsm::kubernetes::ContainerId::toU64(oldest_id);
    ASSERT_TRUE(oldest.has_value());
    EXPECT_FALSE(m_cache.lookupPodUid(*oldest).has_value());
    std::string newest_id = std::to_string(50);
    newest_id.append(64 - newest_id.size(), 'b');
    const auto newest = owlsm::kubernetes::ContainerId::toU64(newest_id);
    ASSERT_TRUE(newest.has_value());
    EXPECT_EQ(m_cache.lookupPodUid(*newest).value_or(""), "pod-uid");
}

TEST_F(NriContainerCacheTest, upsert_marks_owlsm_and_kube_system_flags)
{
    const char* owlsm_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char* kube_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char* other_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const char* owlsm_default_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    m_cache.setOwlsmPodUid("pod-uid-owlsm");
    m_cache.upsert(owlsm_id, "pod-uid-owlsm", "kubepods.slice/ctr.scope", owlsm::globals::KUBE_SYSTEM_NAMESPACE);
    m_cache.upsert(kube_id, "pod-uid-dns", "kubepods.slice/ctr.scope", owlsm::globals::KUBE_SYSTEM_NAMESPACE);
    m_cache.upsert(other_id, "pod-uid-app", "kubepods.slice/ctr.scope", "default");
    m_cache.upsert(owlsm_default_id, "pod-uid-owlsm", "kubepods.slice/ctr.scope", "default");

    const auto owlsm = owlsm::kubernetes::ContainerId::toU64(owlsm_id);
    const auto kube = owlsm::kubernetes::ContainerId::toU64(kube_id);
    const auto other = owlsm::kubernetes::ContainerId::toU64(other_id);
    const auto owlsm_default = owlsm::kubernetes::ContainerId::toU64(owlsm_default_id);
    ASSERT_TRUE(owlsm.has_value());
    ASSERT_TRUE(kube.has_value());
    ASSERT_TRUE(other.has_value());
    ASSERT_TRUE(owlsm_default.has_value());
    EXPECT_EQ(containerValue(*owlsm).id, *owlsm);
    EXPECT_TRUE(containerValue(*owlsm).is_owlsm_container);
    EXPECT_TRUE(containerValue(*owlsm).is_kube_system);
    EXPECT_EQ(containerValue(*kube).id, *kube);
    EXPECT_FALSE(containerValue(*kube).is_owlsm_container);
    EXPECT_TRUE(containerValue(*kube).is_kube_system);
    EXPECT_EQ(containerValue(*other).id, *other);
    EXPECT_FALSE(containerValue(*other).is_owlsm_container);
    EXPECT_FALSE(containerValue(*other).is_kube_system);
    EXPECT_EQ(containerValue(*owlsm_default).id, *owlsm_default);
    EXPECT_TRUE(containerValue(*owlsm_default).is_owlsm_container);
    EXPECT_FALSE(containerValue(*owlsm_default).is_kube_system);
}

TEST_F(NriContainerCacheTest, empty_owlsm_pod_uid_does_not_mark_owlsm)
{
    const char* id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.upsert(id, "pod-uid-owlsm", "kubepods.slice/ctr.scope", "default");
    const auto truncated = owlsm::kubernetes::ContainerId::toU64(id);
    ASSERT_TRUE(truncated.has_value());
    EXPECT_FALSE(containerValue(*truncated).is_owlsm_container);

    m_cache.setOwlsmPodUid("");
    m_cache.upsert(id, "", "kubepods.slice/ctr.scope", "default");
    EXPECT_FALSE(containerValue(*truncated).is_owlsm_container);
}

TEST_F(NriContainerCacheTest, namespace_must_be_exact_kube_system)
{
    const char* empty_ns_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char* null_ns_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char* mixed_case_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    m_cache.upsert(empty_ns_id, "pod-uid-1", "kubepods.slice/ctr.scope", "");
    m_cache.upsert(null_ns_id, "pod-uid-2", "kubepods.slice/ctr.scope", nullptr);
    m_cache.upsert(mixed_case_id, "pod-uid-3", "kubepods.slice/ctr.scope", "Kube-System");

    const auto empty_ns = owlsm::kubernetes::ContainerId::toU64(empty_ns_id);
    const auto null_ns = owlsm::kubernetes::ContainerId::toU64(null_ns_id);
    const auto mixed_case = owlsm::kubernetes::ContainerId::toU64(mixed_case_id);
    ASSERT_TRUE(empty_ns.has_value());
    ASSERT_TRUE(null_ns.has_value());
    ASSERT_TRUE(mixed_case.has_value());
    EXPECT_FALSE(containerValue(*empty_ns).is_kube_system);
    EXPECT_FALSE(containerValue(*null_ns).is_kube_system);
    EXPECT_FALSE(containerValue(*mixed_case).is_kube_system);
}

TEST_F(NriContainerCacheTest, start_reuses_pending_namespace)
{
    const char* id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.setOwlsmPodUid("pod-uid-1");
    m_cache.upsert(id, "pod-uid-1", "kubepods.slice/late.scope", owlsm::globals::KUBE_SYSTEM_NAMESPACE);
    const auto leaf = m_root / "kubepods.slice" / "late.scope";
    std::filesystem::create_directories(leaf);
    m_cache.upsert(id, "", "", "");

    const auto truncated = owlsm::kubernetes::ContainerId::toU64(id);
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(containerValue(*truncated).id, *truncated);
    EXPECT_TRUE(containerValue(*truncated).is_owlsm_container);
    EXPECT_TRUE(containerValue(*truncated).is_kube_system);
}
