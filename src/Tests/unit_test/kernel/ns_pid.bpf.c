#include "shared_unit_tests_structs_definitions.h"
#include "struct_extractors.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, struct ns_pid_helpers_test);
} ns_pid_helpers_test_map SEC(".maps");

SEC("lsm/path_chown")
int BPF_PROG(test_ns_pid_helpers, struct path *path, kuid_t *uid, kgid_t *gid)
{
    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
    {
        return ALLOW;
    }

    const u32 tgid = BPF_CORE_READ(task, tgid);
    struct ns_pid_helpers_test *t = bpf_map_lookup_elem(&ns_pid_helpers_test_map, &tgid);
    if (!t)
    {
        return ALLOW;
    }

    t->ns_pid = get_task_ns_pid(task);
    t->ns_ppid = get_task_ns_ppid(task);
    t->pid_ns_inum = get_task_pid_ns_inum(task);
    t->recorded = 1;
    return ALLOW;
}

char LICENSE[] SEC("license") = "GPL";
