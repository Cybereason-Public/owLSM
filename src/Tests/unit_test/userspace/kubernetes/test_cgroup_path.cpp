#include <gtest/gtest.h>
#include "kubernetes/cgroup_path.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>

class CgroupPathTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_root = std::filesystem::temp_directory_path() /
            ("owlsm_cgroup_path_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::remove_all(m_root);
        std::filesystem::create_directories(m_root);
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_root, error);
    }

    static std::filesystem::path makeDir(const std::filesystem::path& path)
    {
        std::filesystem::create_directories(path);
        return path;
    }

    static std::uint64_t inodeOf(const std::filesystem::path& path)
    {
        struct stat path_stat {};
        EXPECT_EQ(stat(path.c_str(), &path_stat), 0);
        return static_cast<std::uint64_t>(path_stat.st_ino);
    }

    std::filesystem::path m_root;
};

TEST_F(CgroupPathTest, relative_path_joins_host_root_and_returns_inode)
{
    const auto leaf = makeDir(m_root / "kubepods.slice" / "cri-containerd-abc.scope");
    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(
        m_root, "kubepods.slice/cri-containerd-abc.scope");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(leaf));
}

TEST_F(CgroupPathTest, absolute_path_is_joined_under_host_root)
{
    const auto leaf = makeDir(m_root / "kubepods.slice" / "pod.slice");
    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(
        m_root, "/kubepods.slice/pod.slice");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(leaf));
}

TEST_F(CgroupPathTest, systemd_slice_prefix_name_expands)
{
    const auto leaf = makeDir(m_root / "system.slice" / "cri-containerd-434234.scope");
    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(
        m_root, "system.slice:cri-containerd:434234");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(leaf));
}

TEST_F(CgroupPathTest, nested_systemd_slice_expands)
{
    const auto leaf = makeDir(m_root / "kubepods.slice" / "kubepods-besteffort.slice" /
                              "kubepods-besteffort-podabc.slice" / "cri-containerd-434234.scope");
    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(
        m_root, "kubepods-besteffort-podabc.slice:cri-containerd:434234");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(leaf));
}

TEST_F(CgroupPathTest, kubelet_nested_slice_with_underscores)
{
    const auto leaf = makeDir(m_root / "kubelet.slice" / "kubelet-kubepods.slice" /
                              "kubelet-kubepods-besteffort.slice" /
                              "kubelet-kubepods-besteffort-pod51bbb0b8_2993.slice" /
                              "cri-containerd-d2cb6fbc4a36778f.scope");
    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(
        m_root,
        "kubelet-kubepods-besteffort-pod51bbb0b8_2993.slice:cri-containerd:d2cb6fbc4a36778f");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(leaf));
}

TEST_F(CgroupPathTest, missing_proc_root_is_not_cgroup_v2)
{
    EXPECT_THROW(owlsm::kubernetes::CgroupPath::throwIfNotCgroupV2(m_root / "no-proc"), std::runtime_error);
}

TEST_F(CgroupPathTest, regular_directory_tree_is_not_cgroup_v2)
{
    makeDir(m_root / "1" / "root" / "sys" / "fs" / "cgroup");
    EXPECT_THROW(owlsm::kubernetes::CgroupPath::throwIfNotCgroupV2(m_root), std::runtime_error);
}

TEST_F(CgroupPathTest, single_child_directory_is_used)
{
    const auto parent = makeDir(m_root / "container");
    const auto child = makeDir(parent / "crun-sub");
    std::ofstream(parent / "cgroup.procs") << "";

    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "/container");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(child));
}

TEST_F(CgroupPathTest, two_child_directories_stay_on_parent)
{
    const auto parent = makeDir(m_root / "container");
    makeDir(parent / "a");
    makeDir(parent / "b");

    const auto id = owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "/container");
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, inodeOf(parent));
}

TEST_F(CgroupPathTest, empty_or_missing_path_fails)
{
    EXPECT_FALSE(owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "").has_value());
    EXPECT_FALSE(owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "does-not-exist").has_value());
    EXPECT_FALSE(owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath({}, "kubepods.slice").has_value());
}

TEST_F(CgroupPathTest, invalid_systemd_form_fails)
{
    EXPECT_FALSE(owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "not-a-slice").has_value());
    EXPECT_FALSE(owlsm::kubernetes::CgroupPath::cgroupIdFromCriPath(m_root, "a:b").has_value());
}
