#include "test_base.hpp"
#include "map_populator.hpp"
#include <gtest/gtest.h>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>

struct StructExtractorsGetPathFromPathTestCase 
{ 
    std::string path;
    bool create_path; 
    bool is_directory;
};


void create_chown_delete(const std::string& path, bool create, bool directory)
{
    std::error_code ec;

    std::filesystem::remove(path, ec);
    if (std::filesystem::exists(path, ec)) 
    {
        throw std::runtime_error("Path exists: " + path);
    }

    if (create) 
    {
        if (directory)
        {
            std::filesystem::create_directories(path, ec);
            if (ec) throw std::runtime_error("create_directories");
        }
        else
        {
            std::filesystem::create_directories(std::filesystem::path{path}.parent_path(), ec);
            if (ec) throw std::runtime_error("create_directories parent path");

            std::ofstream os{path};
            if (!std::filesystem::exists(path)) throw std::runtime_error("file create");
        }
    }

    std::string path_to_chown = create ? path : "/opt";
    if (::chown(path_to_chown.c_str(), 0, 0) != 0)
    {
        throw std::runtime_error("chown");
    }

    if (directory)
        std::filesystem::remove_all(path, ec);  
    else
        std::filesystem::remove(path, ec);
}


bool executeBpfProgramGetPathFromPath(auto* skel, const StructExtractorsGetPathFromPathTestCase& test_case, int map_fd)
{
    struct struct_extractors_test t = {};
    std::strncpy(t.path_to_find, test_case.path.c_str(), PATH_MAX - 1);
    t.path_to_find[PATH_MAX - 1] = '\0';
    
    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);

    create_chown_delete(test_case.path, test_case.create_path, test_case.is_directory);
    bpf_map_lookup_elem(map_fd, &key, &t);
    bool result = t.found;
    return result;
}

TEST_F(BpfTestBase, StructExtractors_GetPathFromPath) 
{
    const auto map_fd  = bpf_map__fd(skel->maps.struct_extractors_test_map);
    struct bpf_link *lsm_link = bpf_program__attach_lsm(skel->progs.test_get_path_from_path);
    if (!lsm_link) 
    {
        throw std::runtime_error("run_get_path_from_path_tests attach failed");
    }

    std::string max_path_length = "/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmno";
    std::string path_too_long = "/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmno/abcdefghijklmno";
    std::string to_many_path_components = "/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/";
    std::string path_component_to_long = std::string("/" + std::string(130 , 'a'));
    std::string invalid_path = "tmp/t1";
    std::string weird_path = "/aaaaaa/bbbbbb !%^$&*@().,bb#bb    bbbb/bb/b/b/b/b/cc-=_ cc ccc/.txt";

    // Files
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {max_path_length, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_too_long, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {to_many_path_components, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_component_to_long, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {invalid_path, true, false}, map_fd));
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {weird_path, true, false}, map_fd));

    // Directories
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {max_path_length, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_too_long, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {to_many_path_components, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_component_to_long, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {invalid_path, true, true}, map_fd));
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {weird_path, true, true}, map_fd));
    bpf_link__destroy(lsm_link);
}

bool executeBpfProgramGetCmdFromTask(auto* skel, const std::string& cmd, bool should_find = true)
{
    MapPopulatorTest::clear_string_maps(skel);
    MapPopulatorTest::populate_string_maps(skel, cmd, COMPARISON_TYPE_CONTAINS);
    
    int map_fd  = bpf_map__fd(skel->maps.struct_extractors_test_map);
    struct bpf_link *lsm_link = bpf_program__attach_lsm(skel->progs.test_get_cmd_from_task);
    if (!lsm_link) 
    {
        throw std::runtime_error("run_get_cmd_from_task_tests attach failed");
    }

    struct struct_extractors_test t = {};
    std::strncpy(t.cmd_to_find, cmd.c_str(), CMD_MAX);
    t.cmd_length = cmd.size();
    t.dfa_id = MapPopulatorTest::get_test_id();
    t.found = 0;
    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);

    if (should_find)
    {
        std::system(("echo '" + cmd + "' &>/dev/null").c_str());
    }
    else 
    {
        std::system(std::string("echo random stuff &>/dev/null").c_str());
    }

    bpf_map_lookup_elem(map_fd, &key, &t);
    bpf_link__destroy(lsm_link);
    
    MapPopulatorTest::clear_string_maps(skel);
    
    bool result = t.found;
    return result;
}

TEST_F(BpfTestBase, StructExtractors_GetCmdFromTask)
{
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(-t -f /d *#^@%"!  \"rbz./1b~`c)"));
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(this is the RULE_CMD_MAX length!)"));
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(aaa)"));
    EXPECT_FALSE(executeBpfProgramGetCmdFromTask(skel, R"(aaa)", false));
}

// ---- get_cmd_from_user_argv -------------------------------------------------
// The command line that get_cmd_from_user_argv produces is the argv components
// joined by a single space. Each helper call drives one real execve of /bin/true
// with a fully controlled argv. The BPF program reconstructs the command line of
// every execve on the system but sets `found` only on an exact match with the
// expected string we pass in, so unrelated execs can never affect the result.

// Mirrors MAX_ARGV_COMPONENTS in struct_extractors.bpf.h (a BPF-only header not includable here).
static constexpr int kMaxArgvComponents = 32;

static std::string joinWithSpaces(const std::vector<std::string>& argv)
{
    std::string joined;
    for (size_t i = 0; i < argv.size(); ++i)
    {
        if (i != 0)
        {
            joined += ' ';
        }
        joined += argv[i];
    }
    return joined;
}

static bool execveCmdMatches(auto* skel, const std::vector<std::string>& argv, const std::string& expected)
{
    const int map_fd = bpf_map__fd(skel->maps.get_cmd_from_user_argv_test_map);
    struct bpf_link* link = bpf_program__attach(skel->progs.test_get_cmd_from_user_argv);
    if (!link)
    {
        throw std::runtime_error("test_get_cmd_from_user_argv attach failed");
    }

    struct get_cmd_from_user_argv_test t = {};
    std::strncpy(t.expected, expected.c_str(), CMD_MAX - 1);
    t.expected_length = expected.size();
    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);

    pid_t child = fork();
    if (child < 0)
    {
        bpf_link__destroy(link);
        throw std::runtime_error("fork failed");
    }
    if (child == 0)
    {
        std::vector<char*> c_argv;
        for (const auto& arg : argv)
        {
            c_argv.push_back(const_cast<char*>(arg.c_str()));
        }
        c_argv.push_back(nullptr);

        char* empty_env[] = { nullptr };
        execve("/bin/true", c_argv.data(), empty_env); // /bin/true ignores argv and exits 0
        _exit(127);                                     // only reached if execve fails
    }

    waitpid(child, nullptr, 0);
    bpf_map_lookup_elem(map_fd, &key, &t);
    bpf_link__destroy(link);

    return t.found;
}

// A single argv component is reconstructed verbatim, with no separators added.
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_SingleArgument)
{
    const std::vector<std::string> argv = {"solo-argument"};
    EXPECT_TRUE(execveCmdMatches(skel, argv, joinWithSpaces(argv)));
}

// Multiple argv components are joined by exactly one space each.
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_MultipleArgumentsJoinedBySpaces)
{
    const std::vector<std::string> argv = {"alpha", "beta", "gamma"};
    EXPECT_TRUE(execveCmdMatches(skel, argv, joinWithSpaces(argv)));
}

// Special characters and spaces *inside* a single component are preserved byte-for-byte.
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_PreservesSpecialCharactersAndInnerSpaces)
{
    const std::vector<std::string> argv = {"cmd-x", "--path=/a b/c", R"(weird!@#$%^&*()_+)"};
    EXPECT_TRUE(execveCmdMatches(skel, argv, joinWithSpaces(argv)));
}

// A command line longer than CMD_MAX is truncated to exactly CMD_MAX-1 bytes (tests the clamp).
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_TruncatesAtCmdMax)
{
    const std::vector<std::string> argv = {std::string(200, 'a'), std::string(100, 'b')};
    const std::string expected = joinWithSpaces(argv).substr(0, CMD_MAX - 1);
    EXPECT_TRUE(execveCmdMatches(skel, argv, expected));
}

// Only the first MAX_ARGV_COMPONENTS components are read; the rest are dropped.
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_StopsAtMaxArgvComponents)
{
    std::vector<std::string> argv(kMaxArgvComponents + 3, "a"); // more components than the loop reads
    const std::vector<std::string> captured(argv.begin(), argv.begin() + kMaxArgvComponents);
    EXPECT_TRUE(execveCmdMatches(skel, argv, joinWithSpaces(captured)));
}

// The match is exact: a different expected string is not reported as found
// (guards against the harness trivially passing everything).
TEST_F(BpfTestBase, StructExtractors_GetCmdFromUserArgv_NoFalseMatch)
{
    EXPECT_FALSE(execveCmdMatches(skel, {"negative-control"}, "something completely different"));
}