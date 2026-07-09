#include "constants.h"
#include "shared_unit_tests_structs_definitions.h"
#include "struct_extractors.bpf.h"
#include "string_utils.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct struct_extractors_test);
} struct_extractors_test_map SEC(".maps");

SEC("lsm/path_chown")
int BPF_PROG(test_get_path_from_path, struct path *path, kuid_t *uid, kgid_t *gid) 
{
    u32 key = 0;
    struct struct_extractors_test *t = bpf_map_lookup_elem(&struct_extractors_test_map, &key);
    if (!t)
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if(!event)
    {
        return ALLOW;
    }

    if(get_path_from_path(&event->data.chown.file.path, path) <= 0)
    {
        bpf_ringbuf_discard(event, 0);
        return ALLOW;
    }

    if(string_exact_match_known_length(event->data.chown.file.path.value, t->path_to_find, PATH_MAX - 1) == TRUE)
    {
        t->found = TRUE;
    }

    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

SEC("lsm/file_open")
int BPF_PROG(test_get_cmd_from_task, struct file *file)
{
    u32 key = 0;
    struct struct_extractors_test *t = bpf_map_lookup_elem(&struct_extractors_test_map, &key);
    if (!t)
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if(!event)
    {
        return ALLOW;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if(!task)
    {
        goto end_unit_test;
    }

    if(get_cmd_from_task(task, &event->process.cmd) != SUCCESS)
    {
        goto end_unit_test;
    }

    struct string_utils_ctx *sctx = string_utils_setup(event->process.cmd.value, t->cmd_to_find, event->process.cmd.length, t->cmd_length, CMD_MAX);
    if(!sctx)
    {
        goto end_unit_test;
    }
    sctx->idx_to_DFA = t->dfa_id;
    sctx->comparison_type = COMPARISON_TYPE_CONTAINS;

    if(string_contains(sctx) == TRUE)
    {
        t->found = TRUE;
    }

end_unit_test:
    bpf_ringbuf_discard(event, 0);
    return ALLOW;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct get_cmd_from_user_argv_test);
} get_cmd_from_user_argv_test_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int test_get_cmd_from_user_argv(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    struct get_cmd_from_user_argv_test *t = bpf_map_lookup_elem(&get_cmd_from_user_argv_test_map, &key);
    if (!t)
    {
        return 0;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        return 0;
    }

    if (get_cmd_from_user_argv(&event->process.cmd, get_execve_argv_from_ctx(ctx)) != SUCCESS)
    {
        goto end_unit_test;
    }

    if (event->process.cmd.length != t->expected_length)
    {
        goto end_unit_test;
    }
    for (int i = 0; i < CMD_MAX; i++)
    {
        char c = event->process.cmd.value[i];
        if (c != t->expected[i])
        {
            goto end_unit_test;
        }
        if (c == '\0')
        {
            break;
        }
    }
    t->found = TRUE;

end_unit_test:
    bpf_ringbuf_discard(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";