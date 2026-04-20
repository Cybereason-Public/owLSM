I want to create a post with a table that compares between tetragon and owLSM.
In tetragon im speaking about the latest official release version https://github.com/cilium/tetragon/tree/v1.6.1

so im going to list here important things that:
- owLSM has and tetragon doesn't
- tetragon has and owLSM doesn't

# owLSM has and tetragon doesn't
1. enforcment rules substring matching
2. enforcment rules regex matching
3. enforcment rules fieldref matchig (comparing between 2 fields)
4. enforcment rules conditions (and, or, not, parenthesis, etc')
5. enforcment rules use a standard rules language
4. enforcment rule based on full process cmd
x. enforcment rule based on the shell command that was executed
5. Full process info about parent process
6. refrence to the original parent process and not the current one (parent process can change)
7. enforcment rules can be written without linux kernel knowledge (in tetragom rules you must be familiar kernel structs, kernel function arguments, kernel function names, etc)
8. Statefull hooks (owLSM combine data from different hooks to give a statefull rule, while teteragon rules can only use data from current hook)
9. flatbuffers for most efficient communication.


# tetragon has and owLSM doesn't
1. K8S support
2. more enforcment hooks (all LSM hooks and kprobes that support bpf_override_return)
3. observability on more event types.
4. protobuff support



# what I want you to do:
1) Find what is correct?
2) Find more important things that tetragon supports that owLSM doesn't. I don't want all of the things, but only important things that are related to owLSM project goals.

---

## Answers (Tetragon Docs MCP, upstream `cilium/tetragon` documentation)

The notes below are grounded in the official Tetragon documentation surfaced by the **Tetragon Docs** MCP (same material the project publishes for releases such as [v1.6.1](https://github.com/cilium/tetragon/tree/v1.6.1)). They are not a line-by-line audit of that tag.

### 1) What is correct in your lists?

**Generally accurate (with wording tweaks)**

| Your claim | Verdict | Notes from docs |
|------------|---------|-------------------|
| Sigma-style / standard detection language | **Accurate** | Tetragon uses `TracingPolicy` (Kubernetes CRD-style YAML), not Sigma. Docs caution that policies are powerful and need Linux kernel and container knowledge. |
| Regex in **in-kernel** `matchArgs` | **Mostly accurate** | Documented `matchArgs` operators include `Equal`, `NotEqual`, `Prefix`, `Postfix`, `Mask`, `FileType`, `NotFileType` — not general-purpose regex. (You can still use regex in **client-side** tools like `jq` on exported JSON.) |
| “Substring” matching | **Partially accurate** | Tetragon has **prefix** and **postfix** string matching on arguments, not arbitrary “contains anywhere” substring matching. |
| Field-ref / rich boolean (and/or/not/parens) vs Sigma | **Directionally accurate** | Selectors combine filters with fixed rules (e.g. all filters in one selector are AND; multiple selectors on a hook are OR with first-match wins). This is not Sigma’s general boolean expression model. |
| Stateful correlation across hooks in **policy** | **Directionally accurate** | Tetragon stresses in-kernel filtering and actions per hook; cross-hook “state machine in one rule” is not the same model as a dedicated rules engine combining hook state. (Tetragon still maintains process metadata for events.) |
| FlatBuffers vs protobuf | **Accurate for wire format** | Tetragon documents gRPC / protobuf APIs and JSON event output; it does not position FlatBuffers as the primary export path. |
| K8s-first ops | **Accurate** | Helm install, `TracingPolicy` CRD, `kubectl` workflows are first-class; policies can also be loaded via `tetra` or daemon flags on non-K8s systems. |
| More hook types / coverage for observability | **Accurate** | Docs list kprobes, tracepoints, uprobes, LSM hooks, USDTs, with wide argument typing for kernel introspection. |
| “More enforcement hooks (LSM + kprobes with override)” | **Mostly accurate, kernel-dependent** | Docs describe `Override` on kprobes/uprobes (via kernel error injection / `CONFIG_BPF_KPROBE_OVERRIDE`), LSM BPF hooks, and signal-based enforcement. Feature probes (e.g. `tetra probe`) can show `lsm: false` on kernels where BPF LSM is unavailable — so LSM is not universal on every deployment. |

**Needs correction**

| Your claim | Verdict | Why |
|------------|---------|-----|
| “Full process info about parent” / “Tetragon doesn’t” | **Inaccurate** | gRPC API docs describe `parent` on events and **`ancestors`** (chain beyond immediate parent). Tetragon clearly exposes parent process context. |
| “Enforcement rule based on shell command only owLSM has” | **Overstated** | Tetragon documents **uprobes** (e.g. hooking `readline` in `/bin/bash`) for shell-oriented visibility. That is not identical to owLSM’s model, but it is not fair to say Tetragon has no shell-level story. |

**Numbering** | Fix duplicate “4” / “5” in your first list when you turn this into a public post.

---

### 2) Additional **Tetragon** strengths vs **owLSM** (aligned with owLSM’s goals: prevention, detection, Linux endpoint)

Pick a subset for the table; all are documentation-backed:

1. **Kubernetes workload identity** — Namespace, pod, and workload metadata on events for cluster-scoped detection and response (stated explicitly in the overview).
2. **Policy library and guided use cases** — Large catalog (process, file, network, credentials, host integrity, BPF activity, etc.) for fast rollout.
3. **Uprobes / USDTs** — User-space and language-runtime hooking (e.g. bash `readline`) alongside kernel probes.
4. **Tracepoints** — Stable kernel interfaces for portable policies vs many kprobe symbol/version hazards.
5. **Rich kernel argument typing** — Many structured types (`file`, `sock`, `cred`, `linux_binprm`, …) for deep inspection in policies.
6. **Dual enforcement style** — `Override` return values (where the kernel allows) plus **signals** (e.g. `SIGKILL`); docs note trade-offs and combining them.
7. **Process loader events** — Dedicated visibility into dynamic library loads (relevant to hijacking and dependency risk).
8. **Credentials and privilege monitoring** — Dedicated docs and policies for capability / credential changes at syscall and kernel layers.
9. **IMA-backed file hashes on LSM paths** — Optional `imaHash` on supported LSM hooks for integrity-style evidence (where IMA/kernel allow).
10. **Operations / ecosystem** — Prometheus metrics reference, exporter configuration, Cilium-oriented deployment story, `tetra` CLI for live events and policy management.

---

### Suggested one-line caveat for the blog post

Both projects evolve; for Tetragon, call out **kernel and configuration prerequisites** (BTF, BPF LSM, override support, `tetra probe`) so comparisons stay fair for readers on mixed fleets.
