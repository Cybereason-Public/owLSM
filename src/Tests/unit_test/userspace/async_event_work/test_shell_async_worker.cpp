#include <gtest/gtest.h>
#include "async_event_work/shell_async_worker.hpp"
#include "events/event.hpp"
#include "shell_detection/shell_types.hpp"
#include "shell_detection/shell_binary_info.hpp"

#include <memory>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <climits>

namespace owlsm::events
{

class ShellAsyncWorkerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_worker = std::make_unique<ShellAsyncWorker>();
    }

    void TearDown() override
    {
        m_worker.reset();
    }

    std::shared_ptr<Event> createEvent(unsigned long inode, unsigned int dev, unsigned long long last_modified_seconds, const std::string& path)
    {
        auto event = std::make_shared<Event>();
        event->process.file.inode = inode;
        event->process.file.dev = dev;
        event->process.file.last_modified_seconds = last_modified_seconds;
        event->process.file.path.value = path;
        return event;
    }

    std::unordered_set<FileKey, FileKeyHash>& getNonShellsCache()
    {
        return m_worker->m_non_shells_quick_cache;
    }

    std::unordered_set<FileKey, FileKeyHash>& getKnownShellsCache()
    {
        return m_worker->m_known_shells_quick_cache;
    }

    void processItem(std::shared_ptr<Event>& event)
    {
        m_worker->processItem(event);
    }

    std::unique_ptr<ShellAsyncWorker> m_worker;
};

// ============== FileKey Tests ==============

TEST_F(ShellAsyncWorkerTest, FileKey_same_inputs_equal)
{
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 100, 1000000};
    EXPECT_EQ(key1, key2);
}

TEST_F(ShellAsyncWorkerTest, FileKey_different_inode_not_equal)
{
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12346, 100, 1000000};
    EXPECT_NE(key1, key2);
}

TEST_F(ShellAsyncWorkerTest, FileKey_different_dev_not_equal)
{
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 101, 1000000};
    EXPECT_NE(key1, key2);
}

TEST_F(ShellAsyncWorkerTest, FileKey_different_mtime_not_equal)
{
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 100, 1000001};
    EXPECT_NE(key1, key2);
}

TEST_F(ShellAsyncWorkerTest, FileKeyHash_same_for_equal_keys)
{
    FileKeyHash hasher;
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 100, 1000000};
    EXPECT_EQ(hasher(key1), hasher(key2));
}

TEST_F(ShellAsyncWorkerTest, FileKeyHash_different_for_different_keys)
{
    FileKeyHash hasher;
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12346, 100, 1000000};
    const FileKey key3{12345, 101, 1000000};
    EXPECT_NE(hasher(key1), hasher(key2));
    EXPECT_NE(hasher(key1), hasher(key3));
}

// ============== distributeIfNeeded Tests ==============

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_non_shell_adds_to_cache)
{
    if (!std::filesystem::exists("/usr/bin/ls"))
    {
        GTEST_SKIP() << "/usr/bin/ls not found";
    }

    auto event = createEvent(12345, 100, 1000000, "/usr/bin/ls");
    const FileKey expected_key{12345, 100, 1000000};

    EXPECT_TRUE(getNonShellsCache().empty());
    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(expected_key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_nonexistent_path_adds_to_cache)
{
    auto event = createEvent(99999, 100, 1000000, "/nonexistent/path/to/binary");
    const FileKey expected_key{99999, 100, 1000000};

    EXPECT_TRUE(getNonShellsCache().empty());
    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(expected_key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_cached_non_shell_returns_early)
{
    auto event = createEvent(12345, 100, 1000000, "/usr/bin/ls");
    const FileKey key{12345, 100, 1000000};

    getNonShellsCache().insert(key);

    const auto cache_size_before = getNonShellsCache().size();
    m_worker->distributeIfNeeded(event);
    const auto cache_size_after = getNonShellsCache().size();

    EXPECT_EQ(cache_size_before, cache_size_after);
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_shell_not_added_to_non_shells_cache)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    auto event = createEvent(12345, 100, 1000000, "/usr/bin/bash");
    const FileKey key{12345, 100, 1000000};

    EXPECT_TRUE(getNonShellsCache().empty());
    EXPECT_TRUE(getKnownShellsCache().empty());
    m_worker->distributeIfNeeded(event);
    EXPECT_FALSE(getNonShellsCache().contains(key));
    EXPECT_TRUE(getKnownShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_known_shell_returns_before_shell_check)
{
    auto event = createEvent(12345, 100, 1000000, "/nonexistent/path/to/binary");
    const FileKey key{12345, 100, 1000000};

    getKnownShellsCache().insert(key);
    m_worker->distributeIfNeeded(event);

    EXPECT_TRUE(getNonShellsCache().empty());
    EXPECT_TRUE(getKnownShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_same_shell_cached_once)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    auto first_event = createEvent(12345, 100, 1000000, "/usr/bin/bash");
    auto second_event = createEvent(12345, 100, 1000000, "/usr/bin/bash");
    const FileKey key{12345, 100, 1000000};

    m_worker->distributeIfNeeded(first_event);
    m_worker->distributeIfNeeded(second_event);

    EXPECT_EQ(getKnownShellsCache().size(), 1u);
    EXPECT_TRUE(getKnownShellsCache().contains(key));
    EXPECT_TRUE(getNonShellsCache().empty());
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_same_shell_path_different_mtime_cached_separately)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    auto event1 = createEvent(12345, 100, 1000000, "/usr/bin/bash");
    auto event2 = createEvent(12345, 100, 2000000, "/usr/bin/bash");
    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 100, 2000000};

    m_worker->distributeIfNeeded(event1);
    m_worker->distributeIfNeeded(event2);

    EXPECT_TRUE(getKnownShellsCache().contains(key1));
    EXPECT_TRUE(getKnownShellsCache().contains(key2));
    EXPECT_EQ(getKnownShellsCache().size(), 2u);
}

TEST_F(ShellAsyncWorkerTest, processItem_failed_shell_info_removes_known_shell)
{
    auto event = createEvent(12345, 100, 1000000, "/nonexistent/path/to/binary");
    const FileKey key{12345, 100, 1000000};

    getKnownShellsCache().insert(key);
    processItem(event);

    EXPECT_FALSE(getKnownShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_text_file_adds_to_cache)
{
    const std::string temp_file = "/tmp/test_shell_async_worker_text.txt";
    {
        std::ofstream ofs(temp_file);
        ofs << "not a binary";
    }

    auto event = createEvent(88888, 100, 1000000, temp_file);
    const FileKey expected_key{88888, 100, 1000000};

    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(expected_key));

    std::filesystem::remove(temp_file);
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_multiple_non_shells_cached)
{
    auto event1 = createEvent(11111, 100, 1000000, "/nonexistent/path1");
    auto event2 = createEvent(22222, 100, 2000000, "/nonexistent/path2");
    auto event3 = createEvent(33333, 100, 3000000, "/nonexistent/path3");

    m_worker->distributeIfNeeded(event1);
    m_worker->distributeIfNeeded(event2);
    m_worker->distributeIfNeeded(event3);

    EXPECT_EQ(getNonShellsCache().size(), 3u);
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_same_inode_different_mtime_cached_separately)
{
    auto event1 = createEvent(12345, 100, 1000000, "/nonexistent/path1");
    auto event2 = createEvent(12345, 100, 2000000, "/nonexistent/path2");

    const FileKey key1{12345, 100, 1000000};
    const FileKey key2{12345, 100, 2000000};

    m_worker->distributeIfNeeded(event1);
    m_worker->distributeIfNeeded(event2);

    EXPECT_TRUE(getNonShellsCache().contains(key1));
    EXPECT_TRUE(getNonShellsCache().contains(key2));
}

// ============== Worker Thread Tests ==============

TEST_F(ShellAsyncWorkerTest, start_and_stop_does_not_crash)
{
    EXPECT_NO_THROW(m_worker->start());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_NO_THROW(m_worker->stop());
}

TEST_F(ShellAsyncWorkerTest, start_stop_multiple_times)
{
    for (int i = 0; i < 3; ++i)
    {
        m_worker = std::make_unique<ShellAsyncWorker>();
        EXPECT_NO_THROW(m_worker->start());
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        EXPECT_NO_THROW(m_worker->stop());
        m_worker.reset();
    }
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_shell_event_does_not_crash)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    // Note: We don't start the worker because processItem() requires
    // g_shells_db and g_probe_manager to be initialized, which they aren't
    // in the test environment. This test just verifies distributeIfNeeded works.
    auto event = createEvent(12345, 100, 1000000, "/usr/bin/bash");
    EXPECT_NO_THROW(m_worker->distributeIfNeeded(event));
}

// ============== Edge Cases ==============

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_empty_path)
{
    auto event = createEvent(12345, 100, 1000000, "");
    const FileKey key{12345, 100, 1000000};

    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_large_inode_value)
{
    auto event = createEvent(ULONG_MAX, 100, 1000000, "/nonexistent/path");
    const FileKey key{ULONG_MAX, 100, 1000000};

    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_large_mtime_value)
{
    auto event = createEvent(12345, 100, ULLONG_MAX, "/nonexistent/path");
    const FileKey key{12345, 100, ULLONG_MAX};

    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(key));
}

TEST_F(ShellAsyncWorkerTest, distributeIfNeeded_large_dev_value)
{
    auto event = createEvent(12345, UINT_MAX, 1000000, "/nonexistent/path");
    const FileKey key{12345, UINT_MAX, 1000000};

    m_worker->distributeIfNeeded(event);
    EXPECT_TRUE(getNonShellsCache().contains(key));
}

}

