I want to add K8s support to owLSM.
Im advanced in eBPF and Linux but a begginer in K8s. 
However, I did a short syllabus that I asked an LLM to generate regarding what I need to know to add K8s support to owLSM. Now im after finishing the syllabus.

I want to start plan and design the K8s support, including tests. 

# Things to better understand
- `Tetragon: TracingPolicy + Kernel Enforcement + K8s integration` in the syllabus, module 5. 

# Things we need
Here are list of things we need and how owLSM competitors do it.
All of the data is from the syllabus and wasn't doubled check by me.

- DaemonSet: We will use a DemonSet to deploy the agent in every node of the cluster.
- know when a pod is created: we will need a way to know when a pod/container is created. Best if we can do it in the agent itself, even better if we can do it using eBPF.
- map a kernel event to a K8s pod identity.
    + How falco does it: syscall event → libsinsp → container engine API → K8s API cache → enriched event with pod name/namespace/labels
        * Calls container engine API (containerd gRPC / Docker socket) to map container PID → container ID → image name
        * Uses the K8S API to create and maintain a cache of `container_id → {pod_name, namespace, labels}` and watches pod events to know when a cache update is needed (new pod, dead pod).
    + How tetragon does it: For each pod tetragon gets the container's cgroup_id -> has a bpf map `cgroup_id -> pod_metadata` which it uses to enrich with container metadata -> Use in-memory K8s cache (Like falco) to enrich event with K8s data

- pod targeted enforcement: Similar to Tetragon. Tetragon has a map of `container_id (cgroup_id) -> does this policy apply`


