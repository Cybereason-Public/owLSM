#include "error_reports.bpf.h"
#include "allocators.bpf.h"

const volatile enum log_level log_level_to_print;

statfunc struct error_report_t * allocate_empty_error_report_t()
{
    struct error_report_t *error = bpf_ringbuf_reserve(&errors, sizeof(struct error_report_t), 0);
    if(!error)
    {
        bpf_printk("[%s] bpf_ringbuf_reserve failed", __func__);
        return NULL;
    }
    if(bpf_probe_read_kernel(error, sizeof(*error), &empty_error_report_t) != SUCCESS)
    {
        bpf_ringbuf_discard(error, 0);
        bpf_printk("[%s] bpf_probe_read_kernel failed", __func__);
        return NULL;
    }
    return error;
}


void get_hook_name(char *hook_name)
{
    unsigned int key = 0;
    char *hook_name_tmp = bpf_map_lookup_elem(&hook_names, &key);
    if(!hook_name_tmp)
    {
        bpf_printk("%s: bpf_map_lookup_elem failed", __func__);
        return;
    }
    if(bpf_probe_read_kernel_str(hook_name, HOOK_NAME_MAX_LENGTH, hook_name_tmp) < 1)
    {
        bpf_printk("%s: bpf_probe_read_kernel_str failed", __func__);
        return;
    }
}

int report_error(int error_code, const char * location, const char * details)
{
    struct error_report_t *error = allocate_empty_error_report_t();
    if(!error)
    {
        bpf_printk("Failed to allocate memory for report_error");
        return GENERIC_ERROR;
    }

    error->error_code = error_code;
    get_hook_name(error->hook_name);
    bpf_probe_read_kernel_str(error->location, sizeof(error->location), (const void *)location);
    bpf_probe_read_kernel_str(error->details,  sizeof(error->details),  (const void *)details);
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);
    unsigned int current_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_log_printk("[ERROR_REPORT][%s:%s][%s:%d]: %s", error->hook_name, error->location, comm, current_pid, error->details);
    bpf_ringbuf_submit(error, 0);
    return SUCCESS;
}