#include "test_base.hpp"

#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

struct NsPidHelpersSample
{
    unsigned int ns_pid = 0;
    unsigned int ns_ppid = 0;
    unsigned int pid_ns_inum = 0;
};

struct PipePair
{
    int read_fd = -1;
    int write_fd = -1;

    PipePair()
    {
        int fds[2] = {-1, -1};
        if (pipe(fds) != 0)
        {
            throw std::runtime_error("pipe failed");
        }
        read_fd = fds[0];
        write_fd = fds[1];
    }

    ~PipePair()
    {
        if (read_fd >= 0)
        {
            close(read_fd);
        }
        if (write_fd >= 0)
        {
            close(write_fd);
        }
    }

    PipePair(const PipePair&) = delete;
    PipePair& operator=(const PipePair&) = delete;
};

unsigned int currentHostPid()
{
    char buf[32] = {};
    const ssize_t n = readlink("/proc/self", buf, sizeof(buf) - 1);
    if (n <= 0)
    {
        throw std::runtime_error("readlink /proc/self failed");
    }
    return static_cast<unsigned int>(std::stoul(buf));
}

std::vector<unsigned int> readStatusNspids(const unsigned int host_pid)
{
    std::ifstream in("/proc/" + std::to_string(host_pid) + "/status");
    if (!in)
    {
        throw std::runtime_error("failed to open /proc status");
    }
    std::string line;
    while (std::getline(in, line))
    {
        if (line.rfind("NSpid:", 0) != 0)
        {
            continue;
        }
        std::istringstream ss(line.substr(6));
        std::vector<unsigned int> ids;
        unsigned int value = 0;
        while (ss >> value)
        {
            ids.push_back(value);
        }
        if (ids.empty())
        {
            throw std::runtime_error("empty NSpid");
        }
        return ids;
    }
    throw std::runtime_error("NSpid not found");
}

unsigned int readPidNsInum(const unsigned int host_pid)
{
    const auto path = "/proc/" + std::to_string(host_pid) + "/ns/pid";
    char buf[64] = {};
    if (readlink(path.c_str(), buf, sizeof(buf) - 1) <= 0)
    {
        throw std::runtime_error("readlink /proc/pid/ns/pid failed");
    }
    unsigned int inum = 0;
    if (std::sscanf(buf, "pid:[%u]", &inum) != 1)
    {
        throw std::runtime_error(std::string("failed to parse ns/pid: ") + buf);
    }
    return inum;
}

void writeOrExit(const int fd, const void *data, const size_t size)
{
    if (write(fd, data, size) != static_cast<ssize_t>(size))
    {
        _exit(1);
    }
}

void writeOrThrow(const int fd, const void *data, const size_t size)
{
    if (write(fd, data, size) != static_cast<ssize_t>(size))
    {
        throw std::runtime_error("pipe write failed");
    }
}

void readOrThrow(const int fd, void *data, const size_t size)
{
    if (read(fd, data, size) != static_cast<ssize_t>(size))
    {
        throw std::runtime_error("pipe read failed");
    }
}

void pauseForever()
{
    while (true)
    {
        pause();
    }
}

void runIdleChild()
{
    pauseForever();
}

void runTriggerChild(const int report_fd, const int go_fd, const int done_fd, const char *chown_path)
{
    const unsigned int host_pid = currentHostPid();
    writeOrExit(report_fd, &host_pid, sizeof(host_pid));
    char go = 0;
    if (read(go_fd, &go, 1) != 1)
    {
        _exit(1);
    }
    if (chown(chown_path, 0, 0) != 0)
    {
        _exit(1);
    }
    writeOrExit(done_fd, &go, 1);
    pauseForever();
}

std::string createChownFile()
{
    char path[] = "/tmp/owlsm_ns_pid_helpers_XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0)
    {
        throw std::runtime_error("mkstemp failed");
    }
    close(fd);
    return path;
}

void killProcessGroup(const pid_t supervisor_pid)
{
    kill(-supervisor_pid, SIGKILL);
    waitpid(supervisor_pid, nullptr, 0);
}

pid_t forkSupervisor()
{
    const pid_t supervisor_pid = fork();
    if (supervisor_pid < 0)
    {
        throw std::runtime_error("fork supervisor failed");
    }
    if (supervisor_pid == 0)
    {
        if (setpgid(0, 0) != 0)
        {
            _exit(1);
        }
    }
    else
    {
        setpgid(supervisor_pid, supervisor_pid);
    }
    return supervisor_pid;
}

NsPidHelpersSample lookupRecordedSample(auto *skel, const unsigned int host_pid)
{
    const int map_fd = bpf_map__fd(skel->maps.ns_pid_helpers_test_map);
    struct ns_pid_helpers_test value = {};
    if (bpf_map_lookup_elem(map_fd, &host_pid, &value) != 0)
    {
        throw std::runtime_error("ns_pid map lookup failed for pid " + std::to_string(host_pid));
    }
    if (value.recorded != 1)
    {
        throw std::runtime_error("BPF did not record pid " + std::to_string(host_pid));
    }
    bpf_map_delete_elem(map_fd, &host_pid);
    return {value.ns_pid, value.ns_ppid, value.pid_ns_inum};
}

std::vector<NsPidHelpersSample> captureNsPidHelpers(auto *skel, const std::vector<unsigned int> &host_pids, const int go_fd, const int done_fd)
{
    const int map_fd = bpf_map__fd(skel->maps.ns_pid_helpers_test_map);
    const struct ns_pid_helpers_test empty = {};
    for (const unsigned int host_pid : host_pids)
    {
        if (bpf_map_update_elem(map_fd, &host_pid, &empty, BPF_ANY) != 0)
        {
            throw std::runtime_error("failed to insert host pid into ns_pid map");
        }
    }

    struct bpf_link *link = bpf_program__attach_lsm(skel->progs.test_ns_pid_helpers);
    if (!link)
    {
        throw std::runtime_error("test_ns_pid_helpers attach failed");
    }

    for (size_t i = 0; i < host_pids.size(); i++)
    {
        const char go = 1;
        writeOrThrow(go_fd, &go, 1);
    }
    for (size_t i = 0; i < host_pids.size(); i++)
    {
        char done = 0;
        readOrThrow(done_fd, &done, 1);
    }

    std::vector<NsPidHelpersSample> samples;
    samples.reserve(host_pids.size());
    for (const unsigned int host_pid : host_pids)
    {
        samples.push_back(lookupRecordedSample(skel, host_pid));
    }
    bpf_link__destroy(link);
    return samples;
}

NsPidHelpersSample sampleCurrentProcess(auto *skel, const char *chown_path)
{
    const unsigned int host_pid = currentHostPid();
    const int map_fd = bpf_map__fd(skel->maps.ns_pid_helpers_test_map);
    const struct ns_pid_helpers_test empty = {};
    if (bpf_map_update_elem(map_fd, &host_pid, &empty, BPF_ANY) != 0)
    {
        throw std::runtime_error("failed to insert current pid into ns_pid map");
    }

    struct bpf_link *link = bpf_program__attach_lsm(skel->progs.test_ns_pid_helpers);
    if (!link)
    {
        throw std::runtime_error("test_ns_pid_helpers attach failed");
    }
    if (chown(chown_path, 0, 0) != 0)
    {
        bpf_link__destroy(link);
        throw std::runtime_error("chown failed");
    }
    const NsPidHelpersSample sample = lookupRecordedSample(skel, host_pid);
    bpf_link__destroy(link);
    return sample;
}

unsigned int readReportedHostPid(const PipePair &report)
{
    unsigned int host_pid = 0;
    readOrThrow(report.read_fd, &host_pid, sizeof(host_pid));
    return host_pid;
}

TEST_F(BpfTestBase, NsPid_HostPidEqualsNsPid)
{
    const std::string path = createChownFile();
    const unsigned int host_pid = currentHostPid();
    const NsPidHelpersSample sample = sampleCurrentProcess(skel, path.c_str());
    unlink(path.c_str());

    EXPECT_EQ(sample.ns_pid, host_pid);
    EXPECT_EQ(sample.ns_pid, readStatusNspids(host_pid).back());
}

TEST_F(BpfTestBase, NsPid_InnermostNestedPidNamespaceMatchesProcNspid)
{
    const std::string path = createChownFile();
    PipePair report;
    PipePair go;
    PipePair done;

    const pid_t supervisor_pid = forkSupervisor();
    if (supervisor_pid == 0)
    {
        if (unshare(CLONE_NEWPID) != 0)
        {
            _exit(1);
        }
        const pid_t a = fork();
        if (a == 0)
        {
            if (unshare(CLONE_NEWPID) != 0)
            {
                _exit(1);
            }
            const pid_t d = fork();
            if (d == 0)
            {
                const pid_t e = fork();
                if (e == 0)
                {
                    runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
                }
                if (e < 0)
                {
                    _exit(1);
                }
                runIdleChild();
            }
            if (d < 0)
            {
                _exit(1);
            }
            runIdleChild();
        }
        if (a < 0)
        {
            _exit(1);
        }
        const pid_t b = fork();
        if (b == 0)
        {
            runIdleChild();
        }
        const pid_t c = fork();
        if (c == 0)
        {
            runIdleChild();
        }
        if (b < 0 || c < 0)
        {
            _exit(1);
        }
        runIdleChild();
    }

    const unsigned int innermost_host_pid = readReportedHostPid(report);
    const std::vector<NsPidHelpersSample> samples = captureNsPidHelpers(skel, {innermost_host_pid}, go.write_fd, done.read_fd);
    const std::vector<unsigned int> nspids = readStatusNspids(innermost_host_pid);
    killProcessGroup(supervisor_pid);
    unlink(path.c_str());

    ASSERT_EQ(samples.size(), 1u);
    ASSERT_GE(nspids.size(), 2u);
    EXPECT_NE(samples[0].ns_pid, innermost_host_pid);
    EXPECT_EQ(samples[0].ns_pid, nspids.back());
}

TEST_F(BpfTestBase, NsPidInum_ParentAndChildInDifferentPidNamespaces)
{
    const std::string path = createChownFile();
    PipePair report;
    PipePair go;
    PipePair done;

    const pid_t supervisor_pid = forkSupervisor();
    if (supervisor_pid == 0)
    {
        if (unshare(CLONE_NEWPID) != 0)
        {
            _exit(1);
        }
        const pid_t child = fork();
        if (child == 0)
        {
            runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
        }
        if (child < 0)
        {
            _exit(1);
        }
        runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
    }

    const unsigned int first_host_pid = readReportedHostPid(report);
    const unsigned int second_host_pid = readReportedHostPid(report);
    const std::vector<NsPidHelpersSample> samples = captureNsPidHelpers(skel, {first_host_pid, second_host_pid}, go.write_fd, done.read_fd);
    const unsigned int first_inum = readPidNsInum(first_host_pid);
    const unsigned int second_inum = readPidNsInum(second_host_pid);
    killProcessGroup(supervisor_pid);
    unlink(path.c_str());

    ASSERT_EQ(samples.size(), 2u);
    const bool first_is_parent = samples[0].ns_pid == first_host_pid;
    const NsPidHelpersSample &parent_sample = first_is_parent ? samples[0] : samples[1];
    const NsPidHelpersSample &child_sample = first_is_parent ? samples[1] : samples[0];
    const unsigned int parent_inum = first_is_parent ? first_inum : second_inum;
    const unsigned int child_inum = first_is_parent ? second_inum : first_inum;

    EXPECT_NE(parent_sample.pid_ns_inum, child_sample.pid_ns_inum);
    EXPECT_EQ(parent_sample.pid_ns_inum, parent_inum);
    EXPECT_EQ(child_sample.pid_ns_inum, child_inum);
}

TEST_F(BpfTestBase, NsPpid_ChildInNewPidNamespaceIsZero)
{
    const std::string path = createChownFile();
    PipePair report;
    PipePair go;
    PipePair done;

    const pid_t supervisor_pid = forkSupervisor();
    if (supervisor_pid == 0)
    {
        if (unshare(CLONE_NEWPID) != 0)
        {
            _exit(1);
        }
        const pid_t child = fork();
        if (child == 0)
        {
            runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
        }
        if (child < 0)
        {
            _exit(1);
        }
        runIdleChild();
    }

    const unsigned int child_host_pid = readReportedHostPid(report);
    const std::vector<NsPidHelpersSample> samples = captureNsPidHelpers(skel, {child_host_pid}, go.write_fd, done.read_fd);
    killProcessGroup(supervisor_pid);
    unlink(path.c_str());

    ASSERT_EQ(samples.size(), 1u);
    EXPECT_EQ(samples[0].ns_ppid, 0u);
}

TEST_F(BpfTestBase, NsPpid_SamePidNamespaceMatchesParentNsPid)
{
    const std::string path = createChownFile();
    PipePair report;
    PipePair go;
    PipePair done;

    const pid_t supervisor_pid = forkSupervisor();
    if (supervisor_pid == 0)
    {
        if (unshare(CLONE_NEWPID) != 0)
        {
            _exit(1);
        }
        const pid_t parent = fork();
        if (parent == 0)
        {
            const pid_t child = fork();
            if (child == 0)
            {
                runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
            }
            if (child < 0)
            {
                _exit(1);
            }
            runTriggerChild(report.write_fd, go.read_fd, done.write_fd, path.c_str());
        }
        if (parent < 0)
        {
            _exit(1);
        }
        runIdleChild();
    }

    const unsigned int first_host_pid = readReportedHostPid(report);
    const unsigned int second_host_pid = readReportedHostPid(report);
    const std::vector<NsPidHelpersSample> samples = captureNsPidHelpers(skel, {first_host_pid, second_host_pid}, go.write_fd, done.read_fd);
    killProcessGroup(supervisor_pid);
    unlink(path.c_str());

    ASSERT_EQ(samples.size(), 2u);

    const bool first_is_parent = samples[0].ns_pid == 1;
    const NsPidHelpersSample &parent_sample = first_is_parent ? samples[0] : samples[1];
    const NsPidHelpersSample &child_sample = first_is_parent ? samples[1] : samples[0];
    const unsigned int parent_host_pid = first_is_parent ? first_host_pid : second_host_pid;
    const unsigned int child_host_pid = first_is_parent ? second_host_pid : first_host_pid;

    EXPECT_EQ(parent_sample.ns_pid, 1u);
    EXPECT_EQ(child_sample.ns_ppid, parent_sample.ns_pid);
    EXPECT_NE(child_sample.ns_pid, child_host_pid);
    EXPECT_NE(parent_sample.ns_pid, parent_host_pid);
    EXPECT_NE(child_sample.ns_ppid, parent_host_pid);
}
