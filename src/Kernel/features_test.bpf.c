#include "events_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} probe_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} probe_current_event SEC(".maps");

SEC("lsm/path_chown")
int BPF_PROG(probe_path_chown, struct path *path, kuid_t *uid, kgid_t *gid)
{
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(probe_path_chmod, const struct path *path, umode_t mode)
{
    u32 key = 0;
    struct event_t *event = bpf_ringbuf_reserve(&probe_rb, sizeof(*event), 0);
    if (!event)
    {
        return 0;
    }

    if (bpf_map_update_elem(&probe_current_event, &key, event, BPF_ANY) != 0)
    {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_discard(event, 0);
    return 0;
}
