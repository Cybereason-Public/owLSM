# owLSM Kubernetes Support — Phased Plan

## Goal
Add Kubernetes runtime security to owLSM: deploy on every node, enrich events with pod identity, then (later) target rules and enforcement by pod/ns/labels.

## Principles
- Simplicity first; maturity later.
- One binary only: the agent (DaemonSet). No operator split — the agent also consumes/manages CRDs if we add them.
- Prefer Helm to *install* CRD schemas once (avoid every node racing); the agent watches/applies policy objects.
- Helm/charts much simpler than Tetragon — in-repo first, few knobs.
- Userspace identity before eBPF maps / prevention.
- Prefer CRI inspect for container↔pod mapping early; runtime hooks later if races matter.

---

## Phase 1 — Deploy + userspace identity

Ship a DaemonSet agent that can see the cluster, map containers to pods, and enrich events. No eBPF/rules/prevention changes yet.

### 1a. Packaging & deploy
- Container image for the existing single binary
    + glibc ≥ 2.31
    + unzipped release to /opt/owlsm
    + ca-certificates
    + `ENTRYPOINT ["/opt/owlsm/bin/owlsm"] CMD ["-c", "/etc/owlsm/config.json"]`
    + lightweight distro (ubutnu or something lighter)
- DaemonSet (privileged, host mounts as needed: proc, bpf, CRI socket, etc.)
    + paths to mount:
        * host: `/proc`, container: `/host/proc`
        * host: `/sys/fs/cgroup`, container: `/sys/fs/cgroup`
        * host: `/sys/fs/bpf`, container: `/sys/fs/bpf`
        * CRI socket: one host path from Helm `cri.socketHostPath` (default e.g. `/run/containerd/containerd.sock`. Set to `/var/run/crio/crio.sock` for CRI-O). Mount that socket’s parent dir into the pod (same path as on the host).
        * host: `/sys/kernel/tracing`, container: `/sys/kernel/tracing`
        * host: `/sys/kernel/btf`, container: `/sys/kernel/btf`
        * ConfigMap (K8s object) with a key `config.json` which holds the full owLSM config string. Then we mount this ConfigMap in `/etc/owlsm` and kubelet automatically creates the `/etc/owlsm/config.json` file with the content. 
    + hostNetwork
    + dnsPolicy: ClusterFirstWithHostNet (needed with hostNetwork so API DNS works)
    + `nodeSelector: kubernetes.io/os: linux` - so it runs only on linux nodes. 
    + serviceAccountName
    + `tolerations: [{operator: Exists}]`
    + env `NODE_NAME` from downward API `spec.nodeName` (for node-filtered pod watch)

- code modifications - existing code doesn't expect `/host/proc`. So we will need to make the `/proc` path dinamic, and if its k8s mode then don't assume `/proc` but read a value from values.
The full path (for example `/host/proc`) will be specified in `values.yaml` and be passed to the owlsm binary in this flow `values.yaml rootProcPath` --> `ConfigMap` --> `config.json` --> `owLSM`.
Same flow for CRI socket path: `values.yaml cri.socketHostPath` --> `ConfigMap` --> `config.json` CRI endpoint (e.g. `unix://` + that path) --> `owLSM`.

Remember that both of these paths `rootProcPath` & `cri.socketHostPath` are going through the DaemonSet as well, as it needs to mount them.


- ServiceAccount + minimal RBAC (list/watch pods only)
    + ServiceAccount - Who the agent pod is
    + ClusterRole - list/watch pods
    + ClusterRoleBinding - Links ServiceAccount → ClusterRole cluster-wide
- Config delivery via ConfigMap (flags/paths into the pod)
    + ConfigMap will have only 1 key which is `config.json`. This key will hold the full json that is passed to the owLSM binary.
    + Delivery works likes this: we mount this ConfigMap in `/etc/owlsm` and kubelet automatically creates the `/etc/owlsm/config.json` file with the content. Then the docker entrypoint starts this container and passes to it `/etc/owlsm/config.json`
    + What will be added to the config.json:
        * proc path (e.g. /host/proc)
        * CRI endpoint — same socket as `cri.socketHostPath`.
        * enable K8s API — turn on informer/cache + enrichment
    
- Simple in-repo Helm chart (templates only; no chart repo/publishing)
This folder represents the owLSM helm-chart. Everything that it is going to include.
Most of the k8s files/dirs we created in `### 1a. Packaging & deploy` will be here.
Create these new directory sturcture under the owLSM repo root folder
```
kubernetes
├── kind/           # Used for quick tests, quick installation and in the future will be used in the docs (like tetragon has). Contains a short script (and needed resources) that does `create cluster → build/load image → helm install → smoke check`.
├── Dockerfile      # agent runtime image (not the root CI Dockerfile)
├── chart/          # Helm: Chart.yaml, values.yaml, templates/
└──
    ├── Chart.yaml          # Names the chart (owlsm), version, app version. Helm requires it; identifies the release
    ├── values.yaml         # default values users can override
    └── templates/
        ├── daemonset.yaml
        ├── serviceaccount.yaml
        ├── clusterrole.yaml
        ├── clusterrolebinding.yaml
        └── configmap.yaml
```

### 1b. Userspace K8s identity
- Talk to K8s API; maintain an in-memory pod/ns/label cache (watch/informer). Consider open-source K8s/CRI clients.
    + When owLSM starts, it will use the K8s API and get all the pod/ns/label info of the current node (filter with `spec.nodeName=$NODE_NAME`).
    + Then owLSM userspace will create an in-memory cache (C++ unordered-map or LRU) with all node's pod/ns/label. Lets give this map a psuedo name `pod_uid_to_k8s_info`.
    + The cache key will be pod_uid, and the value will be all the k8s info of that pod  {name, namespace, labels, …}. See what info Tetragon and KubeArmor provide.
    + pod_uid is parsed out of the pod object that the k8s api returns to us. pod_uid is recived via `metadata.uid`
    
- Creating a container_id to pod_uid map. Both of these values are parsed out of the k8s api response. Both are in the same pod object json. Lets give this map a psuedo name of container_id_to_pod_uid.
    + A pod may have multiple containers. Collect **every** `containerID` from `status.containerStatuses[]`, `status.initContainerStatuses[]` (and ephemeral if needed). Each entry has its own id; map **all** of them to the same `pod_uid` (many container_id's to a single pod_uid). Skip entries with empty `containerID`.
    + Strip the runtime prefix (`containerd://`, `cri-o://`, …) and keep the **full 64-char hex** id (same hex as in `/host/proc/<pid>/cgroup`). Tetragon often truncates to ~31 chars — we do **not**. 
    + `pod_uid` from `metadata.uid`. Then: `container_id_to_pod_uid[container_id] = pod_uid`.

- Creating a cgroup_id to container_id map. This is the last piece for `cgroup_id -> pod & k8s info` flow.
This cache will happen at 2 phases, the startup phase and business-logic phase. 
    + At startup phase, when owLSM starts. 
        * use the CRI-socket and call ListContainers (filter only for running). This returns a json with data on each container, including the container_id.
        * For each contaier call `ContainerStatus(container_id)`. This will return a json with the cgroup_path.
        * **Path normalization:** do not blindly do `/sys/fs/cgroup + path`. Follow Tetragon: resolve host cgroup root + join CRI path (path may be relative/absolute/systemd form), then `stat(...).st_ino` → `cgroup_id`. See Tetragon `pkg/cgidmap/cri.go` & `HostCgroupRoot` / `CgroupPath`.
        * `cgroup_id_to_container_id[cgroup_id] = container_id` (full 64-char hex)
        * Attach eBPF only after CRI cache ready.
    + At runtime, when userspace recieves events from the eBPF. eBPF gives us cgroup_id. which we need to convert to a container_id.
        * Each time we get an event, check if the cgroup_id is in cgroup_id_to_container_id. If yes, done.
        * When cgroup_id isn't in the cgroup_id_to_container_id, we need to get the corresponding container_id and add the pair to the cache.
        * Getting the container id: parse `/host/proc/<event.pid>/cgroup` (Tetragon-style; KubeArmor does not). Copy Tetragon’s parse idea, but keep the **full 64-char** id (do not truncate to 31). See:
         [procsFindDockerId](https://github.com/cilium/tetragon/blob/573c5d71a5336c9055cb886f31e73b31634d4f8c/pkg/sensors/exec/procevents/proc.go#L146)
         [LookupContainerId](https://github.com/cilium/tetragon/blob/573c5d71a5336c9055cb886f31e73b31634d4f8c/pkg/sensors/exec/procevents/proc.go#L59)

- Updating the caches overtime. So we have 3 caches cgroup_id_to_container_id, container_id_to_pod_uid & pod_uid_to_k8s_info. These maps will change when pods will be created/removed, when k8s values will be changed, when cgroup id's will be added/removed, etc.
    + For the maps container_id_to_pod_uid & pod_uid_to_k8s_info, we will be notified by k8s api watcher about any changes. So the watcher will update these. These 2 maps need to be updated at the same time, so they will be proteced by the same read-write lock. Every read/write operation on these maps require this lock.
    + The cgroup_id_to_container_id will be updated, based on the events we get from eBPF. When we see a cgroup_id that isn't in the cache, we need to find its container_id and add it. 
    + When to remove an entry: // TODO

- Enrich outgoing events with pod name, namespace, labels from the cache
    + We will add an k8s enricher to the SyncEventEnrichment. 
    + The flow of an event k8s enrichment is through the 3 caches cgroup_id_to_container_id, container_id_to_pod_uid & pod_uid_to_k8s_info. If any of the maps is missing the needed entry (not including cgroup_id_to_container_id), we can't enrich the event, and we will just log an info-level-log and enrich what we can. 

### 1c. Prove it
- kind (or similar) smoke test: install → agent runs → events show K8s fields
- Basic automation tests for the K8s identity/enrichment path

**Done when:** DaemonSet + chart install on kind; events enriched with pod/ns/labels from API cache.

---

## Phase 2 — eBPF + pod-aware rules

Wire kernel events to pod identity and allow targeting by K8s metadata.

### 2a. Kernel ↔ pod identity
- Userspace: resolve process/cgroup → container → pod (from Phase 1 cache)
- Kernel maps: only `cgroup_id → policy bits` (or similar) — **not** namespaces/labels in eBPF
- Userspace selects matching pods by ns/labels and writes the resulting cgroup entries into the map

### 2b. Rules
- Extend rule/config model for pod, namespace, and label targeting (userspace match → map updates)
- Keep existing Sigma → JSON flow; add K8s match dimensions only as needed

**Done when:** Rules can select by pod/ns/labels and match on real cluster workloads.

---

## Phase 3 — Prevention / enforcement

- Same map shape: enforce allow/deny in kernel by `cgroup_id` (userspace still owns ns/label selection)
- Validate block/allow behavior with automation tests on kind

**Done when:** Policies can prevent matching actions for targeted pods, not only detect.

---

## Phase 4 — Optional maturity (only if needed)

- Convert the single key ConfigMap where the value is a json, to a yaml based config, so we can control every values via the ConfigMap and it is translated to the final json. So everything is controled in yaml and the yaml is translated to json. 
- Runtime hooks (NRI/OCI) for earlier identity / smaller start races
- Helm chart repository / publishing
- CRDs for kubectl-native policies — still the **same agent** watches them (Helm installs CRD schemas)
- Multi-runtime hardening (more CRI types, edge cases)

**Done when:** Chosen items land with clear product justification; complexity stays justified.

---

## Explicitly deferred (not Phase 1)
- Helm repos / publishing
- Real CRI/NRI runtime hooks
- eBPF cgroup↔policy maps, pod/ns/label rules, prevention
- CRDs (optional later; no separate operator app)
- Treating “container monitoring” as a standalone feature (cache/mapping only)

---

## Suggested order of work
1a → 1b → 1c → 2a → 2b → 3 → 4 (pick pieces as needed)
