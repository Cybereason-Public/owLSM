#include "fill_event_structs.bpf.h"
#include "debug_utils.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct file_t);
} fill_file_t_test_map SEC(".maps");

SEC("lsm/path_chown")
int BPF_PROG(test_fill_file_t, struct path *path, kuid_t *uid, kgid_t *gid) 
{
    unsigned int key = 0;
    struct file_t *t = bpf_map_lookup_elem(&fill_file_t_test_map, &key);
    if (!t)
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats_ringbuf();
    if(!event)
    {
        return ALLOW;
    }

    fill_file_t(&event->data.chown.file, path);

    if(event->data.chown.file.inode == t->inode)
    {
        bpf_probe_read_kernel(t, sizeof(*t), &event->data.chown.file);
    }

    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

char LICENSE[] SEC("license") = "GPL";