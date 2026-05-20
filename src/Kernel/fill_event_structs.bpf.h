#pragma once
#include "struct_extractors.bpf.h"
#include "process_cache.bpf.h"
#include "preprocessor_definitions/stat.bpf.h"

statfunc void fill_file_t_numeric_values(struct file_t *file, const struct dentry *dentry, umode_t * mode)
{
    if(mode)
    {
        file->mode = *mode;
    }
    else
    {
        get_mode_from_dentry(dentry, &file->mode);
    }

    get_inode_from_dentry(dentry, &file->inode);
    get_dev_from_dentry(dentry, &file->dev);
    file->unique_inode_id = get_unique_inode_id_from_dentry(dentry);
    get_owner_uid_from_dentry(dentry, &file->owner.uid);
    get_owner_gid_from_dentry(dentry, &file->owner.gid);
    file->type = get_file_type_from_mode(file->mode);
    file->suid = file->mode & S_ISUID ? TRUE : FALSE;
    file->sgid = file->mode & S_ISGID ? TRUE : FALSE;
    file->mode = file->mode & (S_IRWXU|S_IRWXG|S_IRWXO);
    get_last_modified_from_dentry(dentry, &file->last_modified_seconds);
    get_nlink_from_dentry(dentry, &file->nlink);
}

statfunc int fill_file_t(struct file_t *file, const struct path *path)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    fill_file_t_numeric_values(file, dentry, NULL);
    get_path_from_path(&file->path, path);
    get_filename_from_dentry(&file->filename, dentry);
    return SUCCESS;
}

statfunc unsigned long long build_process_unique_id(unsigned long pid, unsigned long long start_time)
{
    return ((__u64)pid << 32) | (start_time >> 32);
}

// should only be directly used only by bprm_committed_creds and fill_process_t()
statfunc void fill_process_t_numeric_values(struct process_t *process_event, struct task_struct *task)
{
    process_event->pid = BPF_CORE_READ(task, tgid);
    process_event->ppid  = BPF_CORE_READ(task, real_parent, tgid); // TODO - This might not be the original ppid. We need to check somehow and decide what to do if its not.
    process_event->start_time = BPF_CORE_READ(task, start_time);

    process_event->ruid = BPF_CORE_READ(task, cred, uid.val);
    process_event->euid = BPF_CORE_READ(task, cred, euid.val);
    process_event->rgid = BPF_CORE_READ(task, cred, gid.val);
    process_event->egid = BPF_CORE_READ(task, cred, egid.val);
    process_event->suid = BPF_CORE_READ(task, cred, suid.val);
    process_event->ptrace_flags = BPF_CORE_READ(task, ptrace);
    process_event->cgroup_id   = bpf_get_current_cgroup_id();
    get_stdio_file_descriptors_at_process_creation_from_task(task, &process_event->stdio_file_descriptors_at_process_creation);

    process_event->unique_process_id = build_process_unique_id(process_event->pid, process_event->start_time);
    process_event->unique_ppid_id = build_process_unique_id(process_event->ppid, BPF_CORE_READ(task, real_parent, start_time));
}

// should only be directly used only by the fork_hook and the get_or_update_parent_process_in_caches().
statfunc int fill_process_t(struct process_t *process_event, struct task_struct *task)
{
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if(!exe_file)
    {
        REPORT_ERROR(GENERIC_ERROR, "Failed to get exe_file from task");
        return GENERIC_ERROR;
    }
    fill_file_t(&process_event->file, &exe_file->f_path);
    get_cmd_from_task(task, &process_event->cmd);
    fill_process_t_numeric_values(process_event, task);
    return SUCCESS;
}

// Should only be used by the on_exec.bpf.c
statfunc int fill_current_process_t(struct process_t *process_event)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    return fill_process_t(process_event, task);
}

statfunc int fill_event_process_from_cache_for_task(struct process_t *process_event, struct task_struct *task)
{
    u32 pid = BPF_CORE_READ(task, tgid);
    struct process_t *process = get_process_from_alive_process_cache(pid);
    if (!process)
    {
        // This will happen for processes that ran before eBPF attached.
        int ret = fill_process_t(process_event, task);
        if (ret == SUCCESS)
        {
            ret = update_process_in_alive_process_cache(pid, process_event);
        }
        return ret;
    }
    if (bpf_probe_read_kernel(process_event, sizeof(struct process_t), process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        process_event = NULL;
        return GENERIC_ERROR;
    }
    return SUCCESS;
}

statfunc int fill_event_process_from_cache(struct process_t *process_event)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    return fill_event_process_from_cache_for_task(process_event, task);
}

statfunc struct process_t *get_or_update_parent_process_in_caches(const struct process_t *child_process)
{
    struct process_t * parent_process = get_process_from_caches(child_process->ppid, child_process->unique_ppid_id);
    if(!parent_process)
    {
        /*
        If the parent process is not in the caches, it means one of few realistic things:
        1) The parent exited long time ago and was deleted from the dead_process_cache_lru_map
        2) The process is a process that we don't track, like a kernel thread. We will add it now to the caches just for the sake of matching.
        3) The parent was created before the ebpf program was attached, died and wasn't reaped yet.

        We can't really do anything with option 1, so we will hope that its number 2 or 3.
        If indeed it was option 1, we will match the rule_t.parent_process against the current parent and not the original parent.
        */
        parent_process = allocate_process_t();
        if(!parent_process)
        {
            REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed. child_process pid: %d, ppid: %d", child_process->pid, child_process->ppid);
            return NULL;
        }

        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
        fill_process_t(parent_process, parent_task);
        if(update_process_in_alive_process_cache(parent_process->pid, parent_process) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "update_process_in_cache. pid: %d", parent_process->pid);
        }
    }
    return parent_process;
}

statfunc int fill_event_parent_process_from_cache(struct process_t *child_process, struct process_t *parent_process)
{
    struct process_t *parent = get_or_update_parent_process_in_caches(child_process);
    if(!parent)
    {
        return GENERIC_ERROR;
    }
    if(bpf_probe_read_kernel(parent_process, sizeof(struct process_t), parent) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return GENERIC_ERROR;
    }
    return SUCCESS;
}

statfunc int fill_chown_event_t(struct chown_event_t *chown_event, const struct path *path)
{
    fill_file_t(&chown_event->file, path);
    return SUCCESS;
}

statfunc int fill_chmod_event_t(struct chmod_event_t *chmod_event, const struct path *path, umode_t mode)
{
    fill_file_t(&chmod_event->file, path);
    chmod_event->requested_mode = mode;
    return SUCCESS;
}

statfunc int fill_exit_event_t(struct exit_event_t *exit_event, long code)
{
    exit_event->exit_code = (u32)code >> 8; 
    exit_event->signal = ((u32)code & 0xFF) & 0x7F;
    return SUCCESS;
}

statfunc int fill_file_create_event_t(struct file_create_event_t *file_create_event, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    fill_file_t_numeric_values(&file_create_event->file, dentry, &mode);
    return get_file_strings_from_path_and_dentry(&file_create_event->file, dir, dentry);
}

static int fill_unlink_event_t(unlink_event_t *unlink_event, const struct path *dir, struct dentry *dentry)
{
    fill_file_t_numeric_values(&unlink_event->file, dentry, NULL);
    return get_file_strings_from_path_and_dentry(&unlink_event->file, dir, dentry);
}

statfunc int fill_write_event_t(struct write_event_t *write_event, const struct file *file, const unsigned long long * event_hash)
{
    struct path f_path = BPF_CORE_READ(file, f_path);
    fill_file_t(&write_event->file, &f_path);
    write_event->event_hash = *event_hash;
    return SUCCESS;
}

statfunc int fill_read_event_t(read_event_t *read_event, const struct file *file, const unsigned long long * event_hash)
{
    struct path f_path = BPF_CORE_READ(file, f_path);
    fill_file_t(&read_event->file, &f_path);
    read_event->event_hash = *event_hash;
    return SUCCESS;
}

statfunc int fill_rename_event_t(struct rename_event_t *rename_event, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
    fill_file_t_numeric_values(&rename_event->source_file, old_dentry, NULL);
    fill_file_t_numeric_values(&rename_event->destination_file, new_dentry, NULL);
    get_file_strings_from_path_and_dentry(&rename_event->source_file, old_dir, old_dentry);
    get_file_strings_from_path_and_dentry(&rename_event->destination_file, new_dir, new_dentry);
    return SUCCESS;
}

static int get_ip_type_number(void *hdr)
{
    unsigned char first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte >> 4) & 0x0f;
}

static int get_inhl(void *hdr)
{
    unsigned char first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte & 0x0f);
}

// Curretly this is unused, But I use it to compare vlaues with other functions when debugging. Currently will fill only ipv4 addresses
statfunc int fill_missing_network_event_members_using_sk_buffer(struct network_event_t *network_event, struct sk_buff *skb)
{
    unsigned short network_header = BPF_CORE_READ(skb, network_header);
    void *head = BPF_CORE_READ(skb, head);
    struct iphdr * iph = (struct iphdr *)(head + network_header);

    int ip_type_number = get_ip_type_number(iph);
    if(ip_type_number == 4)
    {
        network_event->ip_type = AF_INET;
    }
    else if(ip_type_number == 6)
    {
        network_event->ip_type = AF_INET6;
        return SUCCESS; 
    }
    else 
    {
        return NOT_SUPPORTED;
    }

    unsigned char protocol = BPF_CORE_READ(iph, protocol);
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
    {
        return NOT_SUPPORTED;
    }
    network_event->protocol = protocol;

    network_event->addresses.ipv4.destination_ip = BPF_CORE_READ(iph, saddr);
    network_event->addresses.ipv4.source_ip = BPF_CORE_READ(iph, daddr);

    unsigned char ihl = get_inhl(iph);
    void *transport_header = (void *)iph + (ihl * 4); 
    unsigned short ports[2];
    if (bpf_probe_read_kernel(ports, 4, transport_header) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        return GENERIC_ERROR;
    }
    network_event->destination_port = bpf_ntohs(ports[0]);
    network_event->source_port = bpf_ntohs(ports[1]);

    return SUCCESS;
}

statfunc int fill_incomming_connection_network_event_t(struct network_event_t *network_event, struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    network_event->direction = INCOMING;

    unsigned char protocol = BPF_CORE_READ(sk, sk_protocol);
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
    {
        return NOT_SUPPORTED;
    }
    network_event->protocol = protocol;

    unsigned short family = BPF_CORE_READ(req, __req_common.skc_family);
    if(family == AF_INET6)
    {
        BPF_CORE_READ_INTO(&network_event->addresses.ipv6.source_ip, req, __req_common.skc_v6_daddr);

        if(network_event->addresses.ipv6.source_ip[0] == 0 &&
            network_event->addresses.ipv6.source_ip[1] == 0 &&
            network_event->addresses.ipv6.source_ip[2] == bpf_htonl(0x0000ffff))
        {
            family = AF_INET; //  almost certainly IPv4‑mapped IPv6 (v4‑mapped) behavior from a dual‑stack listener.
            network_event->addresses.ipv6.source_ip[2] = 0;
            network_event->addresses.ipv6.source_ip[3] = 0;
        }
    }

    if(family == AF_INET)
    {
        network_event->addresses.ipv4.destination_ip = BPF_CORE_READ(req, __req_common.skc_rcv_saddr);
        network_event->addresses.ipv4.source_ip = BPF_CORE_READ(req, __req_common.skc_daddr);
    }
    else if(family == AF_INET6)
    {
        BPF_CORE_READ_INTO(&network_event->addresses.ipv6.destination_ip, req, __req_common.skc_v6_rcv_saddr);
    }
    else
    {
        return NOT_SUPPORTED;
    }
    network_event->ip_type = family;

    network_event->destination_port = BPF_CORE_READ(req, __req_common.skc_num);
    network_event->source_port = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport));
    
    return SUCCESS;
}

statfunc int fill_outgoing_connection_network_event_t_second_part(struct network_event_t *network_event, struct sock *sk)
{
    if (network_event->ip_type == AF_INET) 
    {
        network_event->addresses.ipv4.source_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    } 
    else if (network_event->ip_type == AF_INET6) 
    {
        BPF_CORE_READ_INTO(&network_event->addresses.ipv6.source_ip, sk, __sk_common.skc_v6_rcv_saddr);
    }
    else
    {
        return NOT_SUPPORTED;
    }
    network_event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);

    return SUCCESS;
}

statfunc int fill_outgoing_connection_network_event_t_first_part(struct network_event_t *network_event, struct sock *sk, struct sockaddr *address)
{
    network_event->direction = OUTGOING;
    network_event->protocol = BPF_CORE_READ(sk, sk_protocol);
    unsigned short family = BPF_CORE_READ(address, sa_family);
    if(family == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        network_event->addresses.ipv4.destination_ip = BPF_CORE_READ(addr_in, sin_addr.s_addr);
        network_event->destination_port = bpf_ntohs(BPF_CORE_READ(addr_in, sin_port));
    }
    else if(family == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        BPF_CORE_READ_INTO(&network_event->addresses.ipv6.destination_ip, addr_in6, sin6_addr);
        network_event->destination_port = bpf_ntohs(BPF_CORE_READ(addr_in6, sin6_port));
    }
    else
    {
        return NOT_SUPPORTED;
    }
    network_event->ip_type = family;
    
    return SUCCESS;
}