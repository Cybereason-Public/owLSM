#include <filesystem>
#include <sys/stat.h>
#include <sys/sysmacros.h> 
#include <sys/syscall.h>
#include <linux/stat.h>
#include <fcntl.h> 
#include <unistd.h>
#include <fstream>
#include <string>
#include <cstring>

#include "test_base.hpp"

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

static enum file_type get_file_type_from_mode(unsigned short mode)
{
    if(S_ISSOCK(mode)) return SOCKET;
    if(S_ISLNK(mode)) return SYMLINK;
    if(S_ISREG(mode)) return REGULAR_FILE;
    if(S_ISDIR(mode)) return DIRECTORY;
    if(S_ISCHR(mode)) return CHAR_DEVICE;
    if(S_ISBLK(mode)) return BLOCK_DEVICE;
    if(S_ISFIFO(mode)) return FIFO;
    return UNKNOWN_FILE_TYPE;
}

std::pair<struct file_t, struct file_t> setup(auto* skel, const std::string& path)
{
    const std::string filename = path.substr(path.find_last_of('/') + 1);
    struct file_t expected, result = {};
    struct statx statx_buf;
    if (syscall(SYS_statx, AT_FDCWD, path.c_str(), AT_SYMLINK_NOFOLLOW, STATX_ALL, &statx_buf) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "file create or statx failed");
    }
    std::strncpy(expected.path.value, path.c_str(), PATH_MAX);
    std::strncpy(expected.filename.value, filename.c_str(), FILENAME_MAX_LENGTH);
    expected.inode = statx_buf.stx_ino;
    expected.dev = (statx_buf.stx_dev_major << MINORBITS) | (statx_buf.stx_dev_minor & MINORMASK);
    expected.owner.uid = statx_buf.stx_uid;
    expected.owner.gid = statx_buf.stx_gid;
    expected.mode = statx_buf.stx_mode & 07777; 
    expected.type = get_file_type_from_mode(statx_buf.stx_mode); 
    expected.suid = (statx_buf.stx_mode & S_ISUID) ? 1 : 0;
    expected.sgid = (statx_buf.stx_mode & S_ISGID) ? 1 : 0;
    expected.last_modified_seconds = static_cast<unsigned long long>(statx_buf.stx_mtime.tv_sec);
    expected.nlink = statx_buf.stx_nlink;
    if(expected.inode == 0 || expected.dev == 0 || expected.mode == 0 || expected.type == 0 || expected.last_modified_seconds == 0)
    {
        throw std::runtime_error("Failed to get valid inode, dev, mode, type or last modified from stat");
    }

    unsigned int key = 0;
    result.inode = expected.inode;
    int map_fd  = bpf_map__fd(skel->maps.fill_file_t_test_map);
    bpf_map_update_elem(map_fd, &key, &result, BPF_ANY);

    struct bpf_link *lsm_link = bpf_program__attach_lsm(skel->progs.test_fill_file_t);
    if (!lsm_link) 
    {
        throw std::system_error(errno, std::generic_category(), "test_fill_file_t attach failed");
    }

    if (::chown(path.c_str(), 0, 0) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "chown");
    }
    bpf_map_lookup_elem(map_fd, &key, &result);
    bpf_link__destroy(lsm_link);

    return {expected, result};
}

TEST_F(BpfTestBase, FillEventStructs_FillFileTTest)
{
    std::error_code ec;
    std::string path = "/tmp/123.txt";
    std::filesystem::remove(path, ec);
    EXPECT_FALSE(std::filesystem::exists(path, ec));

    std::ofstream os{path};
    EXPECT_TRUE(std::filesystem::exists(path, ec));

    const auto [expected, result] = setup(skel, path);
    EXPECT_EQ(result.inode, expected.inode);
    EXPECT_EQ(result.dev, expected.dev);
    EXPECT_STREQ(result.path.value, expected.path.value);
    EXPECT_STREQ(result.filename.value, expected.filename.value);
    EXPECT_EQ(result.owner.uid, expected.owner.uid);
    EXPECT_EQ(result.owner.gid, expected.owner.gid);
    EXPECT_EQ(result.mode, expected.mode);
    EXPECT_EQ(result.type, expected.type);
    EXPECT_EQ(result.suid, expected.suid);
    EXPECT_EQ(result.sgid, expected.sgid);
    EXPECT_EQ(result.last_modified_seconds, expected.last_modified_seconds);
    EXPECT_EQ(result.nlink, expected.nlink);
    
    std::filesystem::remove(path, ec);
    EXPECT_FALSE(std::filesystem::exists(path, ec));
}

TEST_F(BpfTestBase, FillEventStructs_FillFileTTest_Directory)
{
    std::error_code ec;
    std::string path = "/tmp/123.txt";
    std::filesystem::remove(path, ec);
    EXPECT_FALSE(std::filesystem::exists(path, ec));

    std::filesystem::create_directories(path, ec);
    EXPECT_TRUE(std::filesystem::exists(path, ec));

    const auto [expected, result] = setup(skel, path);
    EXPECT_EQ(result.inode, expected.inode);
    EXPECT_EQ(result.dev, expected.dev);
    EXPECT_STREQ(result.path.value, expected.path.value);
    EXPECT_EQ(result.owner.uid, expected.owner.uid);
    EXPECT_EQ(result.owner.gid, expected.owner.gid);
    EXPECT_EQ(result.mode, expected.mode);
    EXPECT_EQ(result.type, expected.type);
    EXPECT_EQ(result.suid, expected.suid);
    EXPECT_EQ(result.sgid, expected.sgid);
    EXPECT_EQ(result.last_modified_seconds, expected.last_modified_seconds);
    EXPECT_EQ(result.nlink, expected.nlink);
    
    std::filesystem::remove(path, ec);
    EXPECT_FALSE(std::filesystem::exists(path, ec));
}