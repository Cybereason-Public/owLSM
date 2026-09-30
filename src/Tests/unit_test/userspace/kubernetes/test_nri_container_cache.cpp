#include <gtest/gtest.h>
#include "kubernetes/nri_container_cache.hpp"
#include "kubernetes/container_id.hpp"

#include <filesystem>
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
    EXPECT_FALSE(m_cache.lookupPodUid(*truncated).has_value());
    EXPECT_FALSE(m_cache.lookupCgroupId(*truncated).has_value());
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(NriContainerCacheTest, clear_empties_maps)
{
    m_cache.upsert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "pod-uid-1",
                   "kubepods.slice/ctr.scope");
    m_cache.clear();
    EXPECT_EQ(m_cache.size(), 0u);
}
