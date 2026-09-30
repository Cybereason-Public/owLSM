package main

/*
#define OWLSM_K8S_CGO
#include "owlsm_k8s.h"
#include <stdlib.h>

static inline void owlsm_k8s_nri_call_upsert(owlsm_k8s_nri_upsert_fn fn, const char* id, const char* uid, const char* path)
{
    if (fn != NULL)
    {
        fn(id, uid, path);
    }
}

static inline void owlsm_k8s_nri_call_remove(owlsm_k8s_nri_remove_fn fn, const char* id)
{
    if (fn != NULL)
    {
        fn(id);
    }
}

static inline void owlsm_k8s_nri_call_sync_done(owlsm_k8s_nri_sync_done_fn fn)
{
    if (fn != NULL)
    {
        fn();
    }
}

static inline void owlsm_k8s_nri_call_disconnected(owlsm_k8s_nri_disconnected_fn fn)
{
    if (fn != NULL)
    {
        fn();
    }
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type nriPlugin struct{}

type nriState struct {
	stub     stub.Stub
	cancel   context.CancelFunc
	stopping bool
	upsert   C.owlsm_k8s_nri_upsert_fn
	remove   C.owlsm_k8s_nri_remove_fn
	syncDone C.owlsm_k8s_nri_sync_done_fn
	disc     C.owlsm_k8s_nri_disconnected_fn
}

var (
	g_nriMu sync.Mutex
	g_nri   *nriState
)

func (p *nriPlugin) Configure(_ context.Context, _, _, _ string) (api.EventMask, error) {
	var mask api.EventMask
	mask.Set(api.Event_POST_CREATE_CONTAINER, api.Event_START_CONTAINER, api.Event_REMOVE_CONTAINER)
	return mask, nil
}

func (p *nriPlugin) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	uids := make(map[string]string, len(pods))
	for _, pod := range pods {
		if pod == nil {
			continue
		}
		uids[pod.GetId()] = pod.GetUid()
	}
	for _, ctr := range containers {
		if ctr == nil {
			continue
		}
		path := ""
		if linux := ctr.GetLinux(); linux != nil {
			path = linux.GetCgroupsPath()
		}
		nriUpsert(ctr.GetId(), uids[ctr.GetPodSandboxId()], path)
	}
	callSyncDone()
	return nil, nil
}

func (p *nriPlugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	return upsertFromNri(pod, ctr)
}

func (p *nriPlugin) StartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	return upsertFromNri(pod, ctr)
}

func (p *nriPlugin) RemoveContainer(_ context.Context, _ *api.PodSandbox, ctr *api.Container) error {
	if ctr == nil {
		return nil
	}
	id := C.CString(ctr.GetId())
	defer C.free(unsafe.Pointer(id))
	g_nriMu.Lock()
	fn := C.owlsm_k8s_nri_remove_fn(nil)
	if g_nri != nil {
		fn = g_nri.remove
	}
	g_nriMu.Unlock()
	C.owlsm_k8s_nri_call_remove(fn, id)
	return nil
}

func upsertFromNri(pod *api.PodSandbox, ctr *api.Container) error {
	if ctr == nil {
		return nil
	}
	uid := ""
	if pod != nil {
		uid = pod.GetUid()
	}
	path := ""
	if linux := ctr.GetLinux(); linux != nil {
		path = linux.GetCgroupsPath()
	}
	nriUpsert(ctr.GetId(), uid, path)
	return nil
}

func nriUpsert(id, uid, path string) {
	cID := C.CString(id)
	cUID := C.CString(uid)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cID))
	defer C.free(unsafe.Pointer(cUID))
	defer C.free(unsafe.Pointer(cPath))
	g_nriMu.Lock()
	fn := C.owlsm_k8s_nri_upsert_fn(nil)
	if g_nri != nil {
		fn = g_nri.upsert
	}
	g_nriMu.Unlock()
	C.owlsm_k8s_nri_call_upsert(fn, cID, cUID, cPath)
}

func callSyncDone() {
	g_nriMu.Lock()
	fn := C.owlsm_k8s_nri_sync_done_fn(nil)
	if g_nri != nil {
		fn = g_nri.syncDone
	}
	g_nriMu.Unlock()
	C.owlsm_k8s_nri_call_sync_done(fn)
}

//export owlsm_k8s_nri_start
func owlsm_k8s_nri_start(onUpsert C.owlsm_k8s_nri_upsert_fn, onRemove C.owlsm_k8s_nri_remove_fn, onSync C.owlsm_k8s_nri_sync_done_fn, onDisc C.owlsm_k8s_nri_disconnected_fn) C.int {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := stub.New(&nriPlugin{},
		stub.WithPluginName("owlsm"),
		stub.WithPluginIdx("01"),
		stub.WithSocketPath(api.DefaultSocketPath),
		stub.WithOnClose(func() {}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "owlsm_k8s: nri stub.New: %v\n", err)
		cancel()
		return -1
	}

	st := &nriState{stub: s, cancel: cancel, upsert: onUpsert, remove: onRemove, syncDone: onSync, disc: onDisc}
	g_nriMu.Lock()
	g_nri = st
	g_nriMu.Unlock()

	if err := s.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "owlsm_k8s: nri stub.Start: %v\n", err)
		g_nriMu.Lock()
		if g_nri == st {
			g_nri = nil
		}
		g_nriMu.Unlock()
		cancel()
		s.Stop()
		return -2
	}

	go func() {
		s.Wait()
		g_nriMu.Lock()
		stopping := st.stopping
		fn := st.disc
		g_nriMu.Unlock()
		if !stopping {
			C.owlsm_k8s_nri_call_disconnected(fn)
		}
	}()
	return 0
}

//export owlsm_k8s_nri_stop
func owlsm_k8s_nri_stop() {
	g_nriMu.Lock()
	st := g_nri
	if st != nil {
		st.stopping = true
	}
	g_nri = nil
	g_nriMu.Unlock()
	if st == nil {
		return
	}
	st.cancel()
	st.stub.Stop()
}
