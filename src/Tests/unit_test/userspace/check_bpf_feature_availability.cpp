#include "check_bpf_feature_availability.hpp"
#include "globals/global_strings.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <cstdint>
#include <unistd.h>

// Test hook: exposes the private static validation helpers of
// owlsm::CheckBpfFeatureAvailability (declared as a friend of that class), so we can
// exercise the tracepoint-offset parsing/validation without constructing the class
// (whose constructor loads BPF feature probes).
class CheckBpfFeatureAvailabilityTest : public ::testing::Test
{
public:
    static int parseTracepointFieldOffset(const std::string& path, const std::string& field)
    {
        return owlsm::CheckBpfFeatureAvailability::parseTracepointFieldOffset(path, field);
    }
    static bool validateArgvOffset(const std::string& path, int expected)
    {
        return owlsm::CheckBpfFeatureAvailability::validateArgvOffset(path, expected);
    }
    static void validateExecArgvOffsets()
    {
        owlsm::CheckBpfFeatureAvailability::validateExecArgvOffsets();
    }

protected:
    // Mirrors an AlmaLinux 9.x sys_enter_execve `format` (note the extra
    // common_preempt_lazy_count line); filename@16, argv@24, envp@32.
    static constexpr const char* kExecveFormat =
        "name: sys_enter_execve\n"
        "ID: 839\n"
        "format:\n"
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
        "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
        "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n"
        "\tfield:unsigned char common_preempt_lazy_count;\toffset:8;\tsize:1;\tsigned:0;\n"
        "\n"
        "\tfield:int __syscall_nr;\toffset:12;\tsize:4;\tsigned:1;\n"
        "\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;\n"
        "\tfield:const char *const * argv;\toffset:24;\tsize:8;\tsigned:0;\n"
        "\tfield:const char *const * envp;\toffset:32;\tsize:8;\tsigned:0;\n"
        "\n"
        "print fmt: \"filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx\", "
        "((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))\n";

    std::filesystem::path m_tmp;

    void TearDown() override
    {
        if (!m_tmp.empty())
        {
            std::error_code ec;
            std::filesystem::remove(m_tmp, ec);
        }
    }

    std::string writeTempFormat(const std::string& content)
    {
        m_tmp = std::filesystem::temp_directory_path() /
                ("owlsm_ut_format_" + std::to_string(::getpid()) + "_" +
                 std::to_string(reinterpret_cast<uintptr_t>(this)));
        std::ofstream out(m_tmp);
        out << content;
        out.close();
        return m_tmp.string();
    }
};

TEST_F(CheckBpfFeatureAvailabilityTest, parse_extracts_each_field_offset)
{
    const std::string path = writeTempFormat(kExecveFormat);
    EXPECT_EQ(parseTracepointFieldOffset(path, "filename"), 16);
    EXPECT_EQ(parseTracepointFieldOffset(path, "argv"), 24);
    EXPECT_EQ(parseTracepointFieldOffset(path, "envp"), 32);
}

TEST_F(CheckBpfFeatureAvailabilityTest, parse_missing_field_returns_minus_one)
{
    const std::string path = writeTempFormat(kExecveFormat);
    EXPECT_EQ(parseTracepointFieldOffset(path, "does_not_exist"), -1);
}

TEST_F(CheckBpfFeatureAvailabilityTest, parse_missing_file_returns_minus_one)
{
    EXPECT_EQ(parseTracepointFieldOffset("/no/such/tracepoint/format", "argv"), -1);
}

TEST_F(CheckBpfFeatureAvailabilityTest, validate_matching_offset_returns_true)
{
    const std::string path = writeTempFormat(kExecveFormat);
    EXPECT_TRUE(validateArgvOffset(path, 24));
}

TEST_F(CheckBpfFeatureAvailabilityTest, validate_mismatched_offset_returns_false)
{
    const std::string path = writeTempFormat(kExecveFormat);
    EXPECT_FALSE(validateArgvOffset(path, 99));
}

TEST_F(CheckBpfFeatureAvailabilityTest, validate_missing_file_returns_false)
{
    // Cannot validate -> warn and report failure, never a hard crash.
    EXPECT_FALSE(validateArgvOffset("/no/such/tracepoint/format", 24));
}

TEST_F(CheckBpfFeatureAvailabilityTest, validate_exec_argv_offsets_on_running_kernel_does_not_throw)
{
    // On every kernel we support, argv sits at the compiled-in offsets, so the real
    // startup check must run cleanly.
    EXPECT_NO_THROW(validateExecArgvOffsets());
}
