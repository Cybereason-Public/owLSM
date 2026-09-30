#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Thin C ABI: client-go informer pushes pod snapshots into C++.
 * C++ maps are the lookup cache (no Go on the hot path).
 *
 * owlsm_k8s_init return codes:
 *   0  success
 *  -1  failed to create in-cluster client
 *  -2  pod informer cache did not sync in time
 *
 * on_upsert: Add or Update.
 * on_delete: Delete, or Update when the UID changed (recreate of ns/name).
 * Pointers passed to callbacks are valid only for the duration of the call.
 */
typedef struct owlsm_k8s_label
{
    char* key;
    char* value;
} owlsm_k8s_label;

typedef struct owlsm_k8s_pod
{
    char* uid;
    char* name;
    char* ns;
    owlsm_k8s_label* labels;
    int label_count;
} owlsm_k8s_pod;

typedef void (*owlsm_k8s_pod_upsert_fn)(const owlsm_k8s_pod* pod);
typedef void (*owlsm_k8s_pod_delete_fn)(const char* uid);

typedef void (*owlsm_k8s_nri_upsert_fn)(const char* container_id,
                                        const char* pod_uid,
                                        const char* cgroups_path);
typedef void (*owlsm_k8s_nri_remove_fn)(const char* container_id);
typedef void (*owlsm_k8s_nri_sync_done_fn)(void);
typedef void (*owlsm_k8s_nri_disconnected_fn)(void);

#ifndef OWLSM_K8S_CGO
int owlsm_k8s_init(const char* node_name,
                   int sync_timeout_ms,
                   owlsm_k8s_pod_upsert_fn on_upsert,
                   owlsm_k8s_pod_delete_fn on_delete);
void owlsm_k8s_destroy(void);

int owlsm_k8s_nri_start(owlsm_k8s_nri_upsert_fn on_upsert,
                        owlsm_k8s_nri_remove_fn on_remove,
                        owlsm_k8s_nri_sync_done_fn on_sync_done,
                        owlsm_k8s_nri_disconnected_fn on_disconnected);
void owlsm_k8s_nri_stop(void);
#endif

#ifdef __cplusplus
}
#endif
