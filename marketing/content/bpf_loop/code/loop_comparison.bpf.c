#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LOOP_COUNT 100

static __noinline long loop_body(u64 index, void *ctx)
{
    if(ctx)
    {
        bpf_printk("index: %d\n", index);
        return 0;
    }
    return 1;
}

SEC("lsm/path_chmod")
int BPF_PROG(probe_bpf_loop, const struct path *path, umode_t mode)
{
    int sum = 0;
    bpf_loop(LOOP_COUNT, loop_body, &sum, 0);
    bpf_printk("sum: %d\n", sum);
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(probe_manual_loop, const struct path *path, umode_t mode)
{
    int sum = 0;
    for (int i = 0; i < LOOP_COUNT; i++)
    {
        loop_body((u64)i, &sum);
    }
    bpf_printk("sum: %d\n", sum);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
