# Tetragon v1.6.1 — process bookkeeping maps vs TracingPolicy enforcement

Pinned release: **[v1.6.1](https://github.com/cilium/tetragon/releases/tag/v1.6.1)**.

“Enforcement rules” here means **`TracingPolicy` / `TracingPolicyNamespaced` selectors + `matchActions`** (in-kernel filter + action), not post-processing JSON.

---

## 1. What is stored in the main process table (`execve_map`)

The canonical BPF definition is **`struct execve_map_value`** keyed by **TGID** (`pid` in `msg_execve_key`).

**C (BPF) — full layout**

- File: [bpf/lib/process.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/lib/process.h)  
- Struct: `struct execve_map_value` (search the file for `struct execve_map_value`).

Per-field summary (same order as in C):

| Field | Meaning (high level) |
|--------|----------------------|
| `key` (`struct msg_execve_key`) | Identity of this thread group: `pid` (TGID) + `ktime` |
| `pkey` (`struct msg_execve_key`) | **Parent** identity (`pid` + `ktime`) as recorded for bookkeeping |
| `flags` | Internal / lifecycle flags |
| `nspid` | PID in the task’s PID namespace (used when selectors use namespace PID mode) |
| `ns` (`struct msg_ns`) | Snapshot of namespace inode numbers (uts, ipc, mnt, pid, net, …) **stored on the map entry** |
| `caps` (`struct msg_capabilities`) | Permitted / effective / inheritable capability masks **stored on the map entry** |
| `bin` (`struct binary`) | Cached **executable path** (full + prefix/postfix helpers), **argv buffer** (`args[]`), and **`matchBinaries` / `followChildren` bitset state** (`mb_bitset`, `mb_gen`) |

`struct binary` is defined in the same file immediately above `execve_map_value` (path chunks + `char args[MAXARGLENGTH]` + match-binary set).

**Go mirror (userspace alignment check)**

- [pkg/sensors/exec/execvemap/execve.go](https://github.com/cilium/tetragon/blob/v1.6.1/pkg/sensors/exec/execvemap/execve.go) — `ExecveValue` with `align:` tags matching the C struct.

**Capabilities layout in BPF**

- [bpf/lib/bpf_cred.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/lib/bpf_cred.h) — `struct msg_capabilities`.

---

## 2. Auxiliary exec bookkeeping (`tg_execve_joined_info_map`)

Not the same as `execve_map`; it **joins complementary exec information across specific exec-related hooks** (see the comment in source).

- Definition + comment: [bpf/lib/process.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/lib/process.h) — search `tg_execve_joined_info_map` and `struct execve_info`.

The file states explicitly that entries are **complementary** and that **core logic should not depend** on this map always being present. Values are `struct execve_info` (e.g. `secureexec`, inode link count / inode number fields — see same `process.h` block).

This is **internal glue** between e.g. `security_bprm_committing_creds` and the `sys_execve` tracepoint path; it is **not** something you address directly in YAML as “read this map”.

---

## 3. What of this data appears in **enforcement** (TracingPolicy)?

You do **not** get arbitrary “read field X from `execve_map`” in the CRD. You get **fixed selector families** that the BPF encoder turns into `selector_process_filter()` logic.

### 3.1 Selectors that consume **`execve_map_value *enter`** (bookkeeping / “who is this process?”)

Implementation entry point:

- [bpf/process/pfilter.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/pfilter.h) — `selector_process_filter(..., struct execve_map_value *enter, struct msg_generic_kprobe *msg)`.

Order of evaluation (same function): **`matchBinaries` → `matchPIDs` → `matchNamespaces` → `matchCapabilities`** (then optional namespace/capability *change* sections if compiled in).

| TracingPolicy concept | Uses `enter` (exec map)? | Code to read |
|------------------------|---------------------------|----------------|
| **`matchBinaries`** | **Yes** — compares against `enter->bin` (path / prefix / postfix maps, `mb_bitset` / parent walk for `followChildren`) | `match_binaries()` in [bpf/process/types/basic.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/types/basic.h); parent-chain bitset updates in [bpf/process/bpf_mbset.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/bpf_mbset.h) (`update_mb_task` walks `pkey` / `execve_map`) |
| **`matchPIDs`** (incl. follow / namespace PID flags) | **Yes** — uses `enter->key.pid`, optionally `enter->nspid`, and can **walk the parent chain** via repeated `execve_map` lookup on `pkey` | Macros `FIND_PIDSET` / `filter_pidsets` at top of [bpf/process/pfilter.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/pfilter.h) |
| **`matchNamespaces`** (in the generic selector pipeline shown above) | **Indirect** — the filter compares selector values to **`msg->ns`** (namespaces attached to the **current** kprobe/LSM message), not by reading `enter->ns` in the snippet path | `process_filter_namespace()` in [bpf/process/pfilter.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/pfilter.h) (`inum = n->inum[nsid]` with `n` from `msg`) |

So: **binary path + argv-sized buffer + match-binary inheritance** and **PID / parent-chain PID logic** are where `execve_map` most clearly feeds **enforcement** selectors.

### 3.2 Selectors / data tied to the **current hook** (`msg`), not the map

| TracingPolicy concept | Primary data source in this BPF path |
|------------------------|--------------------------------------|
| **`matchCapabilities`** | **`msg->caps`** (and `msg->ns` for namespace-scoped cap checks) — see `process_filter_capabilities()` call in [bpf/process/pfilter.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/pfilter.h) |
| **`matchArgs` / `matchData` / `matchReturnArgs`** | Values read from **hooked function arguments** (types / indices in the policy), not from `execve_map_value` |

YAML surface for what exists on **v1.6.1**:

- [pkg/k8s/apis/cilium.io/v1alpha1/types.go](https://github.com/cilium/tetragon/blob/v1.6.1/pkg/k8s/apis/cilium.io/v1alpha1/types.go) — `type KProbeSelector struct` (and the analogous selector structs for uprobes / LSM / tracepoints).

---

## 4. Where `execve_map` rows are created / updated (for “how is it filled?”)

| Lifecycle | BPF file (v1.6.1) |
|-----------|-------------------|
| Exec / process identity refresh | [bpf/process/bpf_execve_event.c](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/bpf_execve_event.c) |
| Fork / new TGID entry | [bpf/process/bpf_fork.c](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/bpf_fork.c) |
| Exit / delete | [bpf/process/bpf_exit.h](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/bpf_exit.h) |
| Late cgroup / metadata updates | [bpf/process/bpf_execve_map_update.c](https://github.com/cilium/tetragon/blob/v1.6.1/bpf/process/bpf_execve_map_update.c) (plus userspace loader wiring in [pkg/sensors/base/base.go](https://github.com/cilium/tetragon/blob/v1.6.1/pkg/sensors/base/base.go) — search `execve_map`) |

---

## 5. One-sentence summary

**`execve_map`** holds per-process **identity (key/pkey)**, **namespaces + caps snapshots**, and a **`binary` bundle (path + args buffer + match-binary bitset)** used heavily for **`matchBinaries`** and **`matchPIDs`** enforcement; other selectors (notably **hook arguments** and some **namespace/cap views**) come from the **current probe’s `msg`**, not from free-form map queries in the policy language.
