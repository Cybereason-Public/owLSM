#include <gtest/gtest.h>

#include "logger.hpp"
#include "globals/global_strings.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

static const std::string DEFAULT_LOG = "/tmp/owlsm_unit_test_default.log";
static const std::string CUSTOM_LOG  = "/tmp/owlsm_unit_test_custom.log";

class LoggerMigrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        fs::remove(DEFAULT_LOG);
        fs::remove(CUSTOM_LOG);
        owlsm::Logger::shutdown();
        owlsm::Logger::initialize(DEFAULT_LOG, LOG_LEVEL_DEBUG, false);
    }

    void TearDown() override
    {
        owlsm::Logger::shutdown();
        fs::remove(DEFAULT_LOG);
        fs::remove(CUSTOM_LOG);
        // Restore the global test logger so other test suites still have a logger.
        // Use sync (false) since spdlog::shutdown() was never called; the thread pool stays alive
        // but we don't want to depend on it here.
        owlsm::Logger::initialize(owlsm::globals::UNIT_TEST_LOG_PATH, LOG_LEVEL_DEBUG, false);
    }

    static bool fileContains(const fs::path& path, const std::string& text)
    {
        std::ifstream f(path);
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return content.find(text) != std::string::npos;
    }

    static bool fileExists(const fs::path& path)
    {
        return fs::exists(path) && fs::is_regular_file(path);
    }

    static bool fileHasContent(const fs::path& path)
    {
        return fileExists(path) && fs::file_size(path) > 0;
    }
};

TEST_F(LoggerMigrationTest, new_path_is_created)
{
    LOG_INFO("before migration");
    owlsm::Logger::applyConfiguredLogLocation(CUSTOM_LOG);

    EXPECT_TRUE(fileExists(CUSTOM_LOG));
}

TEST_F(LoggerMigrationTest, old_path_is_deleted)
{
    LOG_INFO("before migration");
    owlsm::Logger::applyConfiguredLogLocation(CUSTOM_LOG);

    EXPECT_FALSE(fileExists(DEFAULT_LOG));
}

TEST_F(LoggerMigrationTest, logs_written_before_migration_appear_in_new_path)
{
    const std::string pre_migration_msg = "written before path update";
    LOG_INFO(pre_migration_msg);

    owlsm::Logger::applyConfiguredLogLocation(CUSTOM_LOG);

    EXPECT_TRUE(fileContains(CUSTOM_LOG, pre_migration_msg));
}

TEST_F(LoggerMigrationTest, logs_written_after_migration_go_to_new_path)
{
    owlsm::Logger::applyConfiguredLogLocation(CUSTOM_LOG);

    const std::string post_migration_msg = "written after path update";
    LOG_INFO(post_migration_msg);
    owlsm::Logger::shutdown();

    EXPECT_TRUE(fileContains(CUSTOM_LOG, post_migration_msg));
}

TEST_F(LoggerMigrationTest, logs_written_after_migration_do_not_go_to_old_path)
{
    LOG_INFO("before migration");
    owlsm::Logger::applyConfiguredLogLocation(CUSTOM_LOG);

    const std::string post_migration_msg = "only in new file";
    LOG_INFO(post_migration_msg);
    owlsm::Logger::shutdown();

    EXPECT_FALSE(fileContains(DEFAULT_LOG, post_migration_msg));
}

TEST_F(LoggerMigrationTest, noop_when_log_location_is_empty)
{
    LOG_INFO("before noop call");
    owlsm::Logger::applyConfiguredLogLocation("");

    EXPECT_TRUE(fileExists(DEFAULT_LOG));
    EXPECT_FALSE(fileExists(CUSTOM_LOG));
}

TEST_F(LoggerMigrationTest, noop_when_log_location_matches_current_path)
{
    LOG_INFO("before noop call");
    owlsm::Logger::applyConfiguredLogLocation(DEFAULT_LOG);

    EXPECT_TRUE(fileExists(DEFAULT_LOG));
    EXPECT_FALSE(fileExists(CUSTOM_LOG));
}
