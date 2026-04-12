# AGENTS.md - Userspace

## Overview

The Userspace component is a C++ application that loads eBPF programs into the kernel, parses config, populate bpf maps, handles events from ring buffers, enriches events and provides the user interface (CLI). It acts as the control plane for the owLSM system.

---

## Project Structure

```
Userspace/
├── AGENTS.md                       # This file
├── Makefile                        # Build rules
├── main.cpp                        # Entry point
├── ringbuffers_messages_handlers.cpp/.hpp  # Event processing from eBPF
├── configuration/                  # Config file handling
│   └── ...
├── events/                         # Event type definitions, handlers, serializers and enrichment
│   ├── event.hpp                   # C++ event/error structs
│   ├── IEvent_parser.hpp           # Abstract serializer interface
│   ├── event_to_json.hpp/.cpp      # JSON serialization (EventToJson)
│   ├── event_to_flatbuffer.hpp     # FlatBuffers serialization (EventToFlatbuffer)
│   ├── sync_enrichment.hpp         # Synchronous event enrichment
│   └── flatbuffers/                # FlatBuffers schema, generated headers
│       ├── schema/owlsm_events.fbs
│       └── include/owlsm_events_generated.h
├── globals/                        # Global state management
│   └── ...
├── probes_objects/                 # eBPF program loading (libbpf)
│   └── ...
├── rules_managment/                # Rule loading, regex-to-DFA conversion, and bpf map population
│   ├── dfa_builder.hpp/.cpp        # Regex→AST→NFA→DFA pipeline and KMP DFA builder
│   └── ...
└── 3rd_party/                      # Vendored dependencies (DO NOT MODIFY CODE IN THESE FILES)
    ├── cxxopts/                    # CLI parsing
    ├── flatbuffers/                # FlatBuffers runtime headers (v25.12.19)
    ├── magic_enum/                 # Enum reflection
    ├── nlohmann/                   # JSON parsing
    ├── semver/                     # Version handling
    ├── spdlog/                     # Logging
    └── valijson/                   # JSON schema validation
```

## Build Commands

```bash
# Inside Docker container
make userspace -j$(nproc)    # Build userspace (requires kernel built first)
make -j$(nproc)              # Build everything (kernel + userspace)
make clean                   # Clean build artifacts
```

---

## Important Notes

- Requires kernel component to be built first (uses generated skeleton header)
- Must run with root privileges.
- Events and error messages received via ring buffer from eBPF programs

