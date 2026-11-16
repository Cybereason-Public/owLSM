#include "test_base.hpp"
#include <string>
#include <chrono>
#include <thread>

struct event_t executeBpfProgram(int map_fd, int program_fd)
{
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}

    int key = 0;
    struct event_t event = {};
    bpf_map_lookup_elem(map_fd, &key, &event);
    return event;
}

TEST_F(BpfTestBase, EventAllocator_AllocateEventWithBasicStatsRingbufTest)
{
    int map_fd = bpf_map__fd(skel->maps.test_allocate_event_with_basic_stats_ringbuf_map);
    int program_fd = bpf_program__fd(skel->progs.test_allocate_event_with_basic_stats_ringbuf);
    struct event_t event = executeBpfProgram(map_fd, program_fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    struct event_t event2 = executeBpfProgram(map_fd, program_fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    struct event_t event3 = executeBpfProgram(map_fd, program_fd);
    EXPECT_EQ(event.id + 1, event2.id);
    EXPECT_EQ(event2.id + 1, event3.id);

    EXPECT_GT(event.time, 0);
    EXPECT_GT(event2.time, event.time);
    EXPECT_GT(event3.time, event2.time);
}

TEST_F(BpfTestBase, EventAllocator_AllocateEventWithBasicStatsMapTest)
{
    int map_fd = bpf_map__fd(skel->maps.test_allocate_event_with_basic_stats_map_map);
    int program_fd = bpf_program__fd(skel->progs.test_allocate_event_with_basic_stats_map);
    struct event_t event = executeBpfProgram(map_fd, program_fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    struct event_t event2 = executeBpfProgram(map_fd, program_fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    struct event_t event3 = executeBpfProgram(map_fd, program_fd);
    EXPECT_EQ(event.id + 1, event2.id);
    EXPECT_EQ(event2.id + 1, event3.id);

    EXPECT_GT(event.time, 0);
    EXPECT_GT(event2.time, event.time);
    EXPECT_GT(event3.time, event2.time);
}
