
#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"

#define NETWORK_EVENT
#define CONNECT_EVENT
#include "tail_calls_manager.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, unsigned int);
    __type(value, struct event_t);
} sk_outgoing_connections SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(connect_hook, struct socket *sock, struct sockaddr *address, int addrlen)
{
    set_hook_name("connect_hook", 12);
    if(is_current_pid_related())
    {
        return ALLOW;
    }

    struct sock *sk = sock->sk;
    if (!sk) 
    {
        return ALLOW;
    }

    unsigned short protocol = BPF_CORE_READ(sk, sk_protocol);
    if(protocol != IPPROTO_TCP)
    {
        return ALLOW;
    }

    struct event_t * event = bpf_sk_storage_get(&sk_outgoing_connections, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if(!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_sk_storage_get failed");
        return ALLOW;
    }

    event->type = NETWORK;
    int result = fill_outgoing_connection_network_event_t_first_part(&event->data.network, sk, address);
    if(result != SUCCESS && result != NOT_SUPPORTED)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_outgoing_connection_network_event_t_first_part failed");
        goto allow_event;
    }
    if(result == NOT_SUPPORTED)
    {
        goto allow_event;
    }

    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    store_currently_handled_event(event);
    reset_tail_counter();
    do_tail_call(ctx, &connect_prog_array);
    return ALLOW;

allow_event:
    bpf_sk_storage_delete(&sk_outgoing_connections, sk);
    return ALLOW;
}

SEC("lsm/socket_connect")
int BPF_PROG(connect_hook_2, struct socket *sock, struct sockaddr *address, int addrlen)
{
    set_hook_name("connect_hook_2", 14);
    return network_event_tcp_outgoing_tail_call(sock->sk, &sk_outgoing_connections);
}

SEC("lsm/inet_conn_established")
int BPF_PROG(inet_conn_established, struct sock *sk, struct sk_buff *skb)
{
    set_hook_name("inet_conn_established", 21);
    struct event_t * event = bpf_sk_storage_get(&sk_outgoing_connections, sk, 0, 0);
    if(!event)
    {
        return ALLOW;
    }
    event->id = get_next_event_id();
    event->time = bpf_ktime_get_ns();
    if(fill_outgoing_connection_network_event_t_second_part(&event->data.network, sk) != SUCCESS)
    {
        goto discard_sk_storage;
    }
    submit_event(event);

discard_sk_storage:
    bpf_sk_storage_delete(&sk_outgoing_connections, sk);
    return ALLOW;
}

char LICENSE[] SEC("license") = "GPL";