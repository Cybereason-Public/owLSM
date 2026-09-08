#pragma once
#include "preprocessor_definitions/defs.bpf.h"
#include "events_structs.h"

statfunc void print_file_t(const struct file_t *file)
{
    if (!file)
    {
        return;
    }
    bpf_printk("inode=%lu", file->inode);
    bpf_printk("dev=%u", file->dev);
    bpf_printk("unique_inode_id=%llu", file->unique_inode_id);
    bpf_printk("path=%s", file->path.value);
    bpf_printk("owner_uid=%u", file->owner.uid);
    bpf_printk("owner_gid=%u", file->owner.gid);
    bpf_printk("mode=%u", file->mode);
    bpf_printk("type=%d", file->type);
    bpf_printk("suid=%u", file->suid);
    bpf_printk("sgid=%u", file->sgid);
    bpf_printk("last_modified_seconds=%llu", file->last_modified_seconds);
    bpf_printk("nlink=%u", file->nlink);
}

statfunc void print_process_t(const struct process_t *p)
{
    if (!p)
    {
        return;
    }

    bpf_printk("pid=%u", p->pid);
    bpf_printk("ns_pid=%u", p->ns_pid);
    bpf_printk("ppid=%u", p->ppid);
    bpf_printk("ns_ppid=%u", p->ns_ppid);
    bpf_printk("unique_process_id=%llu", p->unique_process_id);
    bpf_printk("unique_ppid_id=%llu", p->unique_ppid_id);

    bpf_printk("ruid=%u",  p->ruid);
    bpf_printk("rgid=%u",  p->rgid);
    bpf_printk("euid=%u",  p->euid);
    bpf_printk("egid=%u",  p->egid);
    bpf_printk("suid=%u",  p->suid);

    bpf_printk("cgroup_id=%llu",  p->cgroup_id);
    bpf_printk("container_id=%llu", p->container_id);
    bpf_printk("start_time=%llu", p->start_time);
    bpf_printk("ptrace_flags=0x%x", p->ptrace_flags);

    print_file_t(&p->file);
    bpf_printk("cmd=%s",  p->cmd.value);
    bpf_printk("shell_command=%s",  p->shell_command.value);
}

statfunc void print_chown_event_t(struct chown_event_t *chown_event)
{
    print_file_t(&chown_event->file);
    bpf_printk("requested_owner_uid=%u", chown_event->requested_owner_uid);
    bpf_printk("requested_owner_gid=%u", chown_event->requested_owner_gid);
}

statfunc void print_chmod_event_t(const struct chmod_event_t *chmod_event)
{
    print_file_t(&chmod_event->file);
    bpf_printk("requested_mode=%d", chmod_event->requested_mode);
}

statfunc void print_fork_event_t(struct fork_event_t *fork_event)
{
}

statfunc void print_exec_event_t(struct exec_event_t *exec_event)
{
    print_process_t(&exec_event->new_process);
}

statfunc void print_exit_event_t(struct exit_event_t *exit_event)
{
    bpf_printk("exit_code=%u", exit_event->exit_code);
    bpf_printk("signal=%u", exit_event->signal);
}

statfunc unsigned long long get_ring_buffer_free_space(void * ring_buffer)
{
    return bpf_ringbuf_query(ring_buffer, BPF_RB_RING_SIZE) - bpf_ringbuf_query(ring_buffer, BPF_RB_AVAIL_DATA);
}