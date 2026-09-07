
# NRI enabled by default
cri-o version that enabled NRI by default: 1.30.0  
cri-o oldest version that isn't EOL: 1.34.0  
containerd version that enabled NRI by default: 2.0.0  
containerd version 1.7.0 will be deprecated in september 2026 (next month), so lets ignore it.  
containerd oldest version that isn't EOL next month: 2.0.0  

So we can assume that NRI will be enabled by default in both cri-o and containerd always. (again ignore soon to be deprecated containerd version 1.7.0)  

# Cgroup v2
We can try and support only cgroup v2 for now.  
Why: 
- owLSM only supports kernel versions 5.14 and above.
- most distro versions with kernel 5.14 and above support cgroup v2 by default. Two classic exceptions are:
  + Ubuntu 20.04 + HWE 5.15
  + Oracle Linux 8 + UEK 5.15/6.x

----

Here is the plan to use NRI instead of using CRI. This only speaks about NRI.

# Support
Containerd version 2.0.0 and above.  
cri-o version 1.30.0 and above.  
linux kernel version 5.14 and above.  
cgroup v2 only.  

We don't support nodes who don't align to these requirements.   

# Caches that we will have
- **pod_uid_to_k8s_info** - key is the pod uid, value is k8s info for the pod (label, namespaces, etc)
    - This is a C++ unordered_map
    - Its a mirror of the go_client cache. Similar to pod_uid_to_info owlsm currently has.
    - This is managed by the go_client informer registered C-callbacks (CPP functions). 
- **container_id_to_pod_uid** - key is truncated u64 container id, value is the pod_uid of that container. 
    - This is a C++ unordered_map
    - This is managed by the NRI.
    - One pod can have multiple container ids. So its a many to one type map. 
- **cgroup_id_to_container_id** - key is cgroup id, value is truncated u64 container id.
    - Both key and value are numbers. 
    - This is a bpf hash map.
    - we only care about the container root cgroup id. So all the cgroup id's here will be of container roots. Not of pods, child-cgroup or anything else. 
- **container_id_to_cgroup_id** - key is truncated u64 container id, value is cgroup id.
    - Both key and value are numbers.
    - This is a C++ unordered_map.
    - Its a reverse cache of cgroup_id_to_container_id, Used for easy cleanup of the cache when a container is removed.


## contianer id truncation to u64
We need to truncate the container id string to 16 characters and convert it to a number. This will happen on the userspace in the NRI plugin after calling `stripRuntimePrefix`.
Truncation only happens in the caches managed by the NRI code, the informer related caches never truncate to a u64, it just `stripRuntimePrefix`. 

In container_id_to_pod_uid, cgroup_id_to_container_id & container_id_to_pod_uid, is always the truncated version. So the code that uses the caches must always use the u64 represention.


### Where stripRuntimePrefix is implemented
depends on our implementation of the NRI plugin code and informer callbacks. This stripRuntimePrefix must only be implemented in a single place in a single language, used by both NRI and the informern. It can be GO or C++. 
We will decide on the implementation language later. 


## Caches initalization
When owLSM starts, it needs to initialize all the caches.  
- **pod_uid_to_k8s_info** - This is initialized by the client_go informer. When informer starts, it itializes its own go caches, and registered C callbacks, it can create such C++ mirror caches. Similar to how owLSM does it now. 
- **cgroup_id_to_container_id, container_id_to_cgroup_id & container_id_to_pod_uid** - Initalization is done via the NRI Synchronize push. When owLSM starts, it will register as an NRI plugin and as part of the handshake it will automatically get a Synchronize dump from the NRI, thus get all the containers and their root Cgroup paths. owLSM will parse the Synchronize dump asap and populate the caches.
We only insert to these caches containers that have non-empty `cgroups_path` and that `stat()` on the cgroup root directory succeeds. Failing `stat()` can mean that the directory doesn't exist anymore which can happen in the exit phase of a container. 

HLD on how container_id_to_pod_uid is initialized and manage is specified in [# HLD on how container_id_to_pod_uid is initialized and managed](#hld-on-how-container_id_to_pod_uid-is-initialized-and-managed)

## Caches update
- **pod_uid_to_k8s_info** - This will be automatically updated by the callbacks that we register with the client_go informer. It has two callbacks `Upsert` & `Delete`. These can be used to manage this cache.
- **cgroup_id_to_container_id, container_id_to_cgroup_id & container_id_to_pod_uid** - Using the NRI. 
    + On each PostCreateContainer event we will get the: pod uid, container id of the new container and its cgroup root path. We can use the cgroup root path with `CgroupPath::cgroupIdFromCriPath` to get the cgroup_id. 
      This allows us to inline update the cgroup_id_to_container_id, container_id_to_cgroup_id & container_id_to_pod_uid for every new container, before any intresting event is triggered for that container. There are events that happen prior to PostCreateContainer, but we won't relate them to this container, we will just relate them to the host. 
    + On each RemoveContainer event, we will remove the entry with that container id from the cache. Its easy to do it in container_id_to_pod_uid & container_id_to_cgroup_id. However cleaning cgroup_id_to_container_id is harder, there might be a race here: Cgroup inodes are reused after rmdir. Late RemoveContainer(A) can delete B’s row if B reused A’s inode. Inorder to solve this we need to check that the key-value pair in container_id_to_cgroup_id & cgroup_id_to_container_id are the same. If cgroup_id points to a different container_id in cgroup_id_to_container_id, we need to only remove the entry from container_id_to_cgroup_id & container_id_to_pod_uid.

### Future possibilities 
If we see that sometimes PostCreateContainer is missing important data that we need or not 100% reliable for any reason, we can have StartContainer as a fallback. So if PostCreateContainer didn't give us everything needed for this container, we can try and extract data with StartContainer.

## Callback logic rules
Connection with the NRI socket can be lost due to 2 reasons:
- **error return code:** When a NRI hook callback is executed (e.g. PostCreateContainer) it must return a return code. This must always be success, as an error code may cause a disconnection. So even if we had an error, log it and return a success code.
- **timeout:** NRI hook callbacks have a timeout which is determined by the K8S admin via `plugin_request_timeout`. We Must return an answer before the timeout. So the logic must be quick as possible, just get the container_id, cgroup_id and update the maps.

## What to do on NRI disconnection 
If the NRI socket got disconnecented for any reason, we must know about the disconnection asap and act.
- **How to know about a disconnection:** `stub.Run(ctx)` blocks until socket dies.  
- **What to do on a disconnection:** Once we know we are disconnected, we just do the connection process again, which will be: reconnecting, initiating a handshake and getting the Synchronize dump, clear the `cgroup_id_to_container_id, container_id_to_cgroup_id & container_id_to_pod_uid` caches and re-populate the caches. yes, while reconnecting we may miss a few event enrichments, but thats ok for now. 
Before reconnecting, ensure that the disconnection wasn't on purpose because owLSM doesn't need the connection anymore (e.g. owlsm is exiting)

## NRI Setup 
- NRI plugin name and index will be `01-owlsm`
- At first we will require the NRI socket.
- In the future we will add support to "Pre-launched plugin" which means we will use NRI even if the socket is disabled ` disable_connections=true`. This is done by dropping our plugin in `/opt/nri/plugins/01-owlsm` (it will require to mount `/opt/nri/plugins/`)


# NRI plugin design

The plugin is owLSM itself. The owlsm process dials `/var/run/nri/nri.sock` (external plugin). A file under `/opt/nri/plugins/01-owlsm` is Phase 4 only (pre-launched plugin).

## Language

The official NRI client is Go (`github.com/containerd/nri/blob/main/pkg/stub/stub.go`). There is no official C++ client.  
client-go does not speak NRI. It talks to the apiserver. NRI talks to the runtime over a Unix socket. We still host the stub in the existing `libowlsm_k8s.so`: same CGO library and process as the informer.

## Shape

```
owlsm (C++)
  └─ libowlsm_k8s.so
       ├─ owlsm_k8s_init        informer goroutine → C upsert/delete → pod_uid_to_k8s_info
       └─ owlsm_k8s_nri_start   stub.Run goroutine → C callbacks → NRI maps + BPF
```

Set identity in code: `WithPluginName("owlsm")` and `WithPluginIdx("01")` in order to get `01-owlsm`.

**Go** owns the socket: register, Configure, Synchronize, PostCreateContainer, RemoveContainer. It extracts `container.id`, `pod.uid`, and `linux.cgroups_path`, then calls C. Always return success to NRI so a `stat` or map error cannot disconnect us or fail the pod.

**C++** owns `CgroupPath::cgroupIdFromCriPath`, the three NRI maps, and the BPF write. `stripRuntimePrefix` and u64 truncation both happen here, in the same function, before any NRI map insert. Go passes the raw container id. The informer never truncates.

On each C upsert: skip if `cgroups_path` is empty or `stat` fails; otherwise strip, truncate and update the three maps (this includes the BPF map work).  
On remove: apply the inode-reuse rule in this document.

## Threads

The stub already has a receive loop. We do not invent a second NRI thread. owlsm starts it, waits for the first Synchronize, and reconnects when `stub.Run` returns unless we called stop (process exiting).

| Thread | Writes | Must not |
|---|---|---|
| Informer CGO | `pod_uid_to_k8s_info` | Touch NRI maps or block NRI |
| NRI CGO | The three NRI maps | Block longer than `plugin_request_timeout` (default 2s); take the informer write lock |
| Event / ringbuffer | — (shared-lock read) | Wait on NRI |

If `pod_uid` is missing from `pod_uid_to_k8s_info`, ship the event without any k8s info from that cache. Just the pod UID. No retry for now.  

Init: informer HasSynced → `owlsm_k8s_nri_start` (block until first Synchronize or timeout). First connect failing in setup throws. Later disconnects: clear the three NRI maps only, handshake again, re-populate. Missed enrichments during reconnect are OK.

`owlsm_k8s_list_running_containers` is replaced by Synchronize.

# Code changes 

## DaemonSet 
- Mount the NRI socket directory  /var/run/nri 
- No need for CRI any more. Remove it. 

## Getting the correct container root cgroup & container_id in eBPF
The eBPF code will need to get the cgroup id for the root Cgroup path for a given container id. We are only using root cgroups, no child cgroups.  
How will it work:
- When we create a process object in the eBPF (Maybe it will be done only in EXEC), we do in a loop `for (i = 0; i < 16; i++)`
  + Call [bpf_get_current_ancestor_cgroup_id(i)](https://docs.ebpf.io/linux/helper-function/bpf_get_current_ancestor_cgroup_id/)
  + If the return value is 0, break.
  + We search each returned cgroup id in the cgroup_id_to_container_id. If found, we save the container_id in the event struct. This will overwrite the previous container_id if there was one.
  + contiue

 It means that we will have the container_id of the highest ancestor_level which is in the cgroup_id_to_container_id, which this is the root cgroup id for the container, and we saved it in the event struct.

- we will add `unsigned long long container_id` as a memeber of the event struct. This will be set by the eBPF code. 

This should work because now we are using NRI and it means everything is inline. It means that we add the cgroup_id and the container_id of the new container in the `PostCreateContainer` hook, before the container actually starts to run user defined code.   
All the events of the container prior to this point will be linked to the host. 

## owlsm process ensures requierments on setup
In owlsm setup phase, when then configurations tell it its in k8s mode, it needs to check the k8s requierments. So it need to check:
- the host uses cgroup v2
- nri setup is successfull (this also includes that the nri socket is available of course)

If any of these setup reqs fail, then we throw and exit.
This will cause a crash loop in owlsm as k8s will re-run its pod, but its ok, its expected. 

# Informer lags NRI
We might have a pod_uid in the container_id_to_pod_uid, but not in the pod_uid_to_k8s_info. If this happens, no retry is needed, just ship the event without the k8s info. (this will be changed later to add a retry queue)

# HLD on how container_id_to_pod_uid is initialized and managed

1) NRI will completely manage the container_id_to_pod_uid cache. Both the initialization and the updateding. And it can do it 100% reliable. 
2) Here are 5 important proto structures:
```
message Container {
  string id = 1;
  string pod_sandbox_id = 2;
  ...
}

// Pod metadata that is considered relevant for a plugin.
message PodSandbox {
  string id = 1;
  string name = 2;
  string uid = 3;
  ...
}

message SynchronizeRequest {
  // Pods known to the runtime.
  repeated PodSandbox pods = 1;
  // Containers known to the runtime.
  repeated Container containers = 2;
  // Whether there are more pods and containers to follow.
  bool more = 3;
}

message RemoveContainerRequest {
  // Pod of removed container.
  PodSandbox pod = 1;
  // Removed container.
  Container container = 2;
}

message PostCreateContainerRequest {
    // Pod of created container.
    PodSandbox pod = 1;
    // Created container.
    Container container = 2;
}

```
3) At Synchronize we will use both pods[] and containers[] to populate container_id_to_pod_uid.
We will iterate containers[] and for each container we will get container.pod_sandbox_id which we will use to find the corresponding pod in pods[].
Now that we found the pod, we get its PodSandbox.uid. 
Now we have both the pod_uid and the container_id and we can insert them into the container_id_to_pod_uid map.

Because we only iterated over containers[] it will ignore infra/pause containers, as they aren't specified in the containers[] list. Which is what we want. 
This is only an HLD of the plan, without real implementation details. However, this must be done in the most time efficient (fastest) way possible. So the algorithm and implementation details here will be chosen in the future.

4) At PostCreateContainer we just extract both container.id and pod.uid and insert them into the container_id_to_pod_uid map.
PostCreateContainer doesn't execute for infra/pause containers. Which is what we want. 

5) At RemoveContainer we just extract both pod.uid and container.id and remove them from the container_id_to_pod_uid map.
RemoveContainer doesn't execute for infra/pause containers. Which is what we want. 