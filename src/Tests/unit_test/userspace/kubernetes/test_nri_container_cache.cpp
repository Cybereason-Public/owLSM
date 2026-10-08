#include <gtest/gtest.h>
#include "kubernetes/nri_container_cache.hpp"
#include "kubernetes/container_id.hpp"

#include <filesystem>
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

    owlsm::kubernetes::NriContainerCache m_cache;
    std::filesystem::path m_root;
};

TEST_F(NriContainerCacheTest, upsert_writes_both_cpp_maps)
{
    const auto cgroup_id = inodeOf(m_root / "kubepods.slice" / "ctr.scope");
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/ctr.scope");

    const auto truncated = owlsm::kubernetes::ContainerId::toU64(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(m_cache.lookupPodUid(*truncated).value_or(""), "pod-uid-1");
    EXPECT_EQ(m_cache.lookupCgroupId(*truncated).value_or(0), cgroup_id);
    EXPECT_EQ(m_cache.size(), 1u);
}

TEST_F(NriContainerCacheTest, empty_path_is_skipped)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "");
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, missing_directory_is_skipped)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/missing.scope");
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, start_reuses_pending_path_after_stat_fails)
{
    const char* id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    m_cache.upsert(id, "pod-uid-1", "kubepods.slice/late.scope");
    EXPECT_EQ(m_cache.size(), 0u);

    const auto leaf = m_root / "kubepods.slice" / "late.scope";
    std::filesystem::create_directories(leaf);
    m_cache.upsert(id, "", "");

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
                   "kubepods.slice/ctr.scope");
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
    m_cache.upsert(id, "pod-uid-1", "kubepods.slice/ctr.scope");
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
    m_cache.upsert(oldest_id, "pod-uid-oldest", "kubepods.slice/ctr.scope");
    m_cache.remove(oldest_id);
    for (int index = 1; index <= 50; ++index)
    {
        std::string id = std::to_string(index);
        id.append(64 - id.size(), 'b');
        m_cache.upsert(id.c_str(), "pod-uid", "kubepods.slice/ctr.scope");
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
