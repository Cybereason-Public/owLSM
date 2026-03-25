---
layout: default
title: Getting Started
nav_order: 2
permalink: /getting-started/
---

# Getting Started

Get owLSM up and running on your Linux system.

## Requirements

Before installing owLSM, ensure your system meets these requirements:

| Requirement | Details |
|-------------|---------|
| **Linux Kernel** | 5.14 or higher |
| **glibc** | 2.31 or higher |
| **eBPF LSM** | Must be enabled in kernel |
| **BTF Support** | Required for CO-RE (Compile Once, Run Everywhere) |
| **Privileges** | owLSM needs to be run as root |

## Build & Installation

For complete build and installation instructions, please refer to the [GitHub repository](https://github.com/cybereason-labs/owLSM).

## Check System Compatibility

Run the script to verify your system meets all requirements.  
The script checks kernel version, glibc version, BTF support, and eBPF LSM support, and reports which requirements pass or fail.

```bash
chmod +x scripts/check_compatibility.sh && ./scripts/check_compatibility.sh
```

## Startup Time

owLSM loads many eBPF programs into the kernel at startup. Each program must pass the kernel's eBPF verifier.
As a result, startup can take **10 to 50 seconds** depending on the system. This is expected behavior — once verification completes, owLSM is fully active and there is no ongoing performance cost from the verifier.

## Shutdown Time

owLSM graceful shutdown takes a few seconds. Once it recived `SIGINT/SIGTERM` signal, it finishing processing all the events that ae already in the pipeline, before it exits.