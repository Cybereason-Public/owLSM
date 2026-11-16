
#include "common_maps.bpf.h"
#include "tail_calls_manager.bpf.h"
#include "allocators.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct event_t);
} test_allocate_event_with_basic_stats_ringbuf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct event_t);
} test_allocate_event_with_basic_stats_map_map SEC(".maps");

SEC("syscall")
unsigned int test_allocate_event_with_basic_stats_ringbuf(struct __sk_buff *skb)
{
    u32 key = 0;
    struct event_t *t = bpf_map_lookup_elem(&test_allocate_event_with_basic_stats_ringbuf_map, &key);
    if(!t)
    {
        return 0;
    }

    struct event_t *event = allocate_event_with_basic_stats_ringbuf();
    if(!event)
    {
        return 0;
    }

    bpf_probe_read_kernel(t, sizeof(*t), event);
    bpf_ringbuf_discard(event, 0);
    return 0;
}

SEC("syscall")
unsigned int test_allocate_event_with_basic_stats_map(struct __sk_buff *skb)
{
    u32 key = 0;
    struct event_t *t = bpf_map_lookup_elem(&test_allocate_event_with_basic_stats_map_map, &key);
    if(!t)
    {
        return 0;
    }

    struct event_t *event = allocate_event_with_basic_stats_map();
    if(!event)
    {
        return 0;
    }

    bpf_probe_read_kernel(t, sizeof(*t), event);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
