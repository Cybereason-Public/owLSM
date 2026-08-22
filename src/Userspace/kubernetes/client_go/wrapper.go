package main

// Thin client-go wrapper: SharedInformer List/Watches pods and pushes
// snapshots into C++ via callbacks. C++ owns the lookup caches.

/*
#define OWLSM_K8S_CGO
#include "owlsm_k8s.h"
#include <stdlib.h>

static inline void owlsm_k8s_call_upsert(owlsm_k8s_pod_upsert_fn fn, const owlsm_k8s_pod* pod)
{
    if (fn != NULL)
    {
        fn(pod);
    }
}

static inline void owlsm_k8s_call_delete(owlsm_k8s_pod_delete_fn fn, const char* uid)
{
    if (fn != NULL)
    {
        fn(uid);
    }
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type runtimeState struct {
	stopCh   chan struct{}
	factory  informers.SharedInformerFactory
	onUpsert C.owlsm_k8s_pod_upsert_fn
	onDelete C.owlsm_k8s_pod_delete_fn
}

var (
	g_mu           sync.Mutex
	g_state        *runtimeState
	g_initializing bool
)

//export owlsm_k8s_init
func owlsm_k8s_init(nodeName *C.char, syncTimeoutMs C.int, onUpsert C.owlsm_k8s_pod_upsert_fn, onDelete C.owlsm_k8s_pod_delete_fn) C.int {
	if !tryBeginInit() {
		return 0
	}

	factory, informer, rc := createPodInformer(nodeName)
	if rc != 0 {
		endInit(nil)
		return rc
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handlePodAdd,
		UpdateFunc: handlePodUpdate,
		DeleteFunc: handlePodDelete,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "owlsm_k8s: AddEventHandler: %v\n", err)
		endInit(nil)
		return -1
	}

	stopCh := make(chan struct{})
	state := &runtimeState{
		stopCh:   stopCh,
		factory:  factory,
		onUpsert: onUpsert,
		onDelete: onDelete,
	}

	// Callbacks must be visible before Start so the initial List Add events reach C++.
	g_mu.Lock()
	g_state = state
	g_mu.Unlock()

	factory.Start(stopCh)
	if !waitForPodCacheSync(informer, syncTimeoutMs) {
		clearAndStop()
		return -2
	}

	g_mu.Lock()
	g_initializing = false
	g_mu.Unlock()
	return 0
}

//export owlsm_k8s_destroy
func owlsm_k8s_destroy() {
	clearAndStop()
}

func tryBeginInit() bool {
	g_mu.Lock()
	defer g_mu.Unlock()
	if g_state != nil || g_initializing {
		return false
	}
	g_initializing = true
	return true
}

func endInit(state *runtimeState) {
	g_mu.Lock()
	g_initializing = false
	g_state = state
	g_mu.Unlock()
}

func clearAndStop() {
	g_mu.Lock()
	state := g_state
	g_state = nil
	g_initializing = false
	g_mu.Unlock()
	if state == nil {
		return
	}
	close(state.stopCh)
}

func createPodInformer(nodeName *C.char) (informers.SharedInformerFactory, cache.SharedIndexInformer, C.int) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "owlsm_k8s: InClusterConfig: %v\n", err)
		return nil, nil, -1
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "owlsm_k8s: NewForConfig: %v\n", err)
		return nil, nil, -1
	}

	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0, nodeNameListOptions(nodeName)...)
	informer := factory.Core().V1().Pods().Informer()
	return factory, informer, 0
}

func nodeNameListOptions(nodeName *C.char) []informers.SharedInformerOption {
	node_name := ""
	if nodeName != nil {
		node_name = C.GoString(nodeName)
	}
	if node_name == "" {
		return nil
	}
	return []informers.SharedInformerOption{
		informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
			lo.FieldSelector = "spec.nodeName=" + node_name
		}),
	}
}

func waitForPodCacheSync(informer cache.SharedIndexInformer, syncTimeoutMs C.int) bool {
	timeout := time.Duration(syncTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return true
	}
	fmt.Fprintf(os.Stderr, "owlsm_k8s: pod informer cache sync timed out\n")
	return false
}

func handlePodAdd(obj interface{}) {
	callUpsert(podFromObj(obj))
}

func handlePodUpdate(oldObj, newObj interface{}) {
	old_pod := podFromObj(oldObj)
	new_pod := podFromObj(newObj)
	if new_pod == nil {
		return
	}
	if old_pod != nil && old_pod.UID != new_pod.UID {
		callDelete(string(old_pod.UID))
	}
	callUpsert(new_pod)
}

func handlePodDelete(obj interface{}) {
	pod := podFromObj(obj)
	if pod == nil {
		return
	}
	callDelete(string(pod.UID))
}

func callUpsert(pod *corev1.Pod) {
	if pod == nil {
		return
	}

	g_mu.Lock()
	var fn C.owlsm_k8s_pod_upsert_fn
	if g_state != nil {
		fn = g_state.onUpsert
	}
	g_mu.Unlock()

	var c_pod C.owlsm_k8s_pod
	copyPodToC(pod, &c_pod)
	defer freePod(&c_pod)
	C.owlsm_k8s_call_upsert(fn, &c_pod)
}

func callDelete(uid string) {
	if uid == "" {
		return
	}

	g_mu.Lock()
	var fn C.owlsm_k8s_pod_delete_fn
	if g_state != nil {
		fn = g_state.onDelete
	}
	g_mu.Unlock()

	c_uid := C.CString(uid)
	defer C.free(unsafe.Pointer(c_uid))
	C.owlsm_k8s_call_delete(fn, c_uid)
}

func copyPodToC(pod *corev1.Pod, out *C.owlsm_k8s_pod) {
	out.uid = C.CString(string(pod.UID))
	out.name = C.CString(pod.Name)
	out.ns = C.CString(pod.Namespace)
	copyLabelsToC(pod.Labels, out)
	copyContainerIDsToC(collectStrippedContainerIDs(pod), out)
}

func copyLabelsToC(labels map[string]string, out *C.owlsm_k8s_pod) {
	n := len(labels)
	if n == 0 {
		return
	}
	ptr := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.owlsm_k8s_label{})))
	if ptr == nil {
		return
	}
	out.labels = (*C.owlsm_k8s_label)(ptr)
	out.label_count = C.int(n)
	slice := unsafe.Slice(out.labels, n)
	i := 0
	for key, value := range labels {
		slice[i].key = C.CString(key)
		slice[i].value = C.CString(value)
		i++
	}
}

func copyContainerIDsToC(ids []string, out *C.owlsm_k8s_pod) {
	n := len(ids)
	if n == 0 {
		return
	}
	ptr := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof((*C.char)(nil))))
	if ptr == nil {
		return
	}
	out.container_ids = (**C.char)(ptr)
	out.container_id_count = C.int(n)
	slice := unsafe.Slice(out.container_ids, n)
	for i, id := range ids {
		slice[i] = C.CString(id)
	}
}

func collectStrippedContainerIDs(pod *corev1.Pod) []string {
	ids := make([]string, 0)
	appendIDs := func(statuses []corev1.ContainerStatus) {
		for _, status := range statuses {
			stripped_id := stripRuntimePrefix(status.ContainerID)
			if stripped_id != "" {
				ids = append(ids, stripped_id)
			}
		}
	}
	appendIDs(pod.Status.ContainerStatuses)
	appendIDs(pod.Status.InitContainerStatuses)
	appendIDs(pod.Status.EphemeralContainerStatuses)
	return ids
}

func stripRuntimePrefix(raw_id string) string {
	if idx := strings.Index(raw_id, "://"); idx >= 0 {
		return raw_id[idx+3:]
	}
	return raw_id
}

func podFromObj(obj interface{}) *corev1.Pod {
	if pod, ok := obj.(*corev1.Pod); ok {
		return pod
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if pod, ok := tombstone.Obj.(*corev1.Pod); ok {
			return pod
		}
	}
	return nil
}

func freePod(pod *C.owlsm_k8s_pod) {
	if pod == nil {
		return
	}
	freeCString(pod.uid)
	freeCString(pod.name)
	freeCString(pod.ns)
	freeLabels(pod)
	freeContainerIDs(pod)
	*pod = C.owlsm_k8s_pod{}
}

func freeCString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func freeLabels(pod *C.owlsm_k8s_pod) {
	if pod.labels == nil {
		return
	}
	if pod.label_count > 0 {
		labels := unsafe.Slice(pod.labels, int(pod.label_count))
		for i := range labels {
			freeCString(labels[i].key)
			freeCString(labels[i].value)
		}
	}
	C.free(unsafe.Pointer(pod.labels))
}

func freeContainerIDs(pod *C.owlsm_k8s_pod) {
	if pod.container_ids == nil {
		return
	}
	if pod.container_id_count > 0 {
		ids := unsafe.Slice(pod.container_ids, int(pod.container_id_count))
		for i := range ids {
			freeCString(ids[i])
		}
	}
	C.free(unsafe.Pointer(pod.container_ids))
}

func main() {}
