
#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "k8s_ignored_events.bpf.h"

#define NETWORK_EVENT
#define ACCEPT_EVENT
#include "tail_calls_manager.bpf.h"

/*
We can't know what hook will run first. Their are 2 scenarios:

1) Server calls accept() -> socket_accept hook fires
accept() blocks waiting for a connection.
Client sends SYN -> inet_conn_request hook fires
TCP handshake completes
accept() returns 

2) Client sends SYN → inet_conn_request hook fires
TCP handshake completes, connection goes to backlog queue
Server calls accept() → socket_accept hook fires
accept() returns immediately, as the connection is alreay in the queue.
*/


struct incoming_connection_tracker_t {
    struct event_t event;
    bool accept_hook;
    bool inet_conn_request_hook;
};

struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, unsigned int);
  __type(value, struct incoming_connection_tracker_t);
} sk_incoming_connections SEC(".maps");


SEC("lsm/socket_accept")
int BPF_PROG(accept_hook, struct socket *sock, struct socket *newsock)
{
    set_hook_name("accept_hook", 11);
    if(is_current_pid_related())
    {
        return ALLOW;
    }

    if(k8s_ignore_current_process())
    {
        return ALLOW;
    }

    struct sock *sk = sock->sk;
    if(!sk)
    {
        return ALLOW;
    }
    if(BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
    {
        return ALLOW;
    }
    
    struct incoming_connection_tracker_t * incoming_connection_tracker = bpf_sk_storage_get(&sk_incoming_connections, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if(!incoming_connection_tracker)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_sk_storage_get failed");
        return ALLOW;
    }
    incoming_connection_tracker->accept_hook = true;

    fill_event_process_from_cache(&incoming_connection_tracker->event.process);
    fill_event_parent_process_from_cache(&incoming_connection_tracker->event.process, &incoming_connection_tracker->event.parent_process);
    if(incoming_connection_tracker->inet_conn_request_hook)
    {
        store_currently_handled_event(&incoming_connection_tracker->event);
        reset_tail_counter();
        do_tail_call(ctx, &accept_prog_array);
    }

    return ALLOW;
}

SEC("lsm/socket_accept")
int BPF_PROG(accept_hook_2, struct socket *sock, struct socket *newsock)
{
    set_hook_name("accept_hook_2", 13);
    return network_event_tcp_incoming_tail_call(sock->sk, &sk_incoming_connections);
}

SEC("lsm/inet_conn_request")
int BPF_PROG(inet_conn_request_hook, struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    set_hook_name("inet_conn_request_hook", 22);
    if(is_current_pid_related())
    {
        return ALLOW;
    }

    struct incoming_connection_tracker_t * incoming_connection_tracker = bpf_sk_storage_get(&sk_incoming_connections, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if(!incoming_connection_tracker)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_sk_storage_get failed");
        return ALLOW;
    }
    incoming_connection_tracker->inet_conn_request_hook = true;
    
    incoming_connection_tracker->event.type = NETWORK;
    int result = fill_incomming_connection_network_event_t(&incoming_connection_tracker->event.data.network, sk, skb, req);
    if(result != SUCCESS && result != NOT_SUPPORTED)
    {
        REPORT_ERROR(GENERIC_ERROR, "[inet_conn_request] fill_incomming_connection_network_event_t failed");
        goto discard_sk_storage;
    }
    if(result == NOT_SUPPORTED)
    {
        goto discard_sk_storage;
    }

    if(incoming_connection_tracker->accept_hook)
    {
        store_currently_handled_event(&incoming_connection_tracker->event);
        reset_tail_counter();
        do_tail_call(ctx, &inet_conn_request_prog_array);
    }
    
    return ALLOW;

discard_sk_storage:
    bpf_sk_storage_delete(&sk_incoming_connections, sk);
    return ALLOW;
}

SEC("lsm/inet_conn_request")
int BPF_PROG(inet_conn_request_hook_2, struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    set_hook_name("inet_conn_request_hook_2", 24);
    return network_event_tcp_incoming_tail_call(sk, &sk_incoming_connections);
}

char LICENSE[] SEC("license") = "GPL";