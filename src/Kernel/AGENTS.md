# AGENTS.md - Kernel (eBPF)

## Overview
The Kernel component contains eBPF programs of many types. Currently: LSM, fentry, uprobes, retuprobe and tracepoint. In the furture we are likely to add more types.
We are mostly intrested in LSM hooks. However, if they can't meet our needs, we will try other inline hook types. And in extremly rare cases, we will consider use async hook types.
These EBPF programs monitor system activity, evaluate security rules, and enforce actions (allow, block, kill process). All code runs in kernel context with strict verifier constraints.

---

## Project Structure

```
Kernel/
├── AGENTS.md                    # This file
├── Makefile                     # eBPF build rules
├── vmlinux.h                    # Kernel type definitions (BTF generated)
├── Programs/
│   ├── syscall_monitoring/      # Syscall hook programs
│   │   ├── on_exec.bpf.c        # Process execution
│   │   ├── on_fork.bpf.c        # Process forking
│   │   ├── on_exit.bpf.c        # Process exit
│   │   ├── on_read.bpf.c        # File read
│   │   ├── on_write.bpf.c       # File write
│   │   ├── on_chmod.bpf.c       # Permission changes
│   │   ├── on_chown.bpf.c       # Ownership changes
│   │   ├── on_unlink.bpf.c      # File deletion
│   │   ├── on_rename.bpf.c      # File rename
│   │   ├── on_file_create.bpf.c # File creation
│   │   └── on_syscall.bpf.c     # Generic syscall handler
│   └── network/                 # Network hook programs
│       ├── on_tcp_incomming.bpf.c
│       └── on_tcp_outgoing.bpf.c
├── common_maps.bpf.c/.h         # Shared BPF maps
├── event_and_rule_matcher.bpf.c/.h  # Rule and event evaluation engine
├── dfa.bpf.c/.h                 # DFA-based string matching (KMP and regex)
├── process_cache.bpf.h          # Process info caching. Only functions in this file are allowed to access the process cache directly. 
├── allocators.bpf.h             # Memory allocation helpers
├── string_utils.bpf.h           # String related utils. Mostly comparison. 
├── struct_extractors.bpf.h      # Data extraction from kernel structs.
├── fill_event_structs.bpf.h     # Event data population
├── prevention.bpf.h             # Action enforcement (block/kill)
├── tail_calls_manager.bpf.h     # Tail call management
├── pids_to_ignore.bpf.h         # PID filtering (ignore specific PID's processes)
├── event_caching.bpf.h          # Event deduplication
├── error_reports.bpf.c/.h       # Error reporting to userspace and logging.
├── debug_utils.h                # Debug macros
└── preprocessor_definitions/    # Build-time configuration
```

---

## Design Concepts

### Event Flow
1. Syscall/network hook triggers → `on_*.bpf.c`
2. Event struct populated → `fill_event_structs.bpf.h`
3. Rules evaluated → `event_and_rule_matcher.bpf.c`
4. Action enforced → `prevention.bpf.h`
5. Event sent to userspace → ring buffer

### Inline hooks
Because we are using inline hooks we can predict and control the flow of system events.
This protects us from many race conditions.For example the alive process cache uses pid as a key and not {pid * process_start_time}. We are attached to the events fork (that creates a pid and inserts to cache) and exit (that releases pid from cache) with inline hooks. So no fear of pid reuse race condition.
We know that a thread syscall or other monitored behavior is blocked until the EBPF code returns.

### Process caches
Their are 2 process caches, one for alive and one for dead processes. Only functions inside process_cache.bpf.h can access the process cache directly.
When EBPF probes get a process object pointer from a process cache, it actually recives a deep copy of that process object. So no changes it does on the proces object actually effects the cache.

### caches for efficiency and usability 
We would like to implement caches where these really help efficiency and usability.
For example we have caches for read/write events, to avoid re-processing the same event multiple times.
This helps both efficiency (as we cache the result of an identical event) and usability as the user isn't spammed with identical events.
---

### Fast Verifier Test Cycle

```bash
# On host - test verifier 
sudo make -C src/Kernel verifier_start -j$(nproc)
```

## Important Notes

- All `.bpf.o` files are merged into `Programs/syscall_monitoring/all_bpf.o`
- Skeleton header generated at `Programs/syscall_monitoring/all_bpf.skel.h`
- Changes to shared headers require full rebuild
- Test verifier on host after any kernel code changes

