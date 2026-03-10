# AGENTS.md

## Project Overview

owLSM is a project for protecting linux machines.
Using EBPF hooks it monitors the system and prevents malicious behavior.

### Components

| Component | Description | Find more info about component at |
|-----------|-------------|-------------------|
| **Kernel** | eBPF programs for syscall/network/other monitoring and rule enforcement | `src/Kernel/AGENTS.md` |
| **Userspace** | C++ program that attaches eBPF programs, manages config and rules, and handles events | `src/Userspace/AGENTS.md` |
| **Shared** | Common headers, files and scripts (constants, structs) used by more then one component. | `src/Shared/AGENTS.md` |
| **RulesGenerator** | Python tool that converts Sigma YAML rules to JSON config | `Rules/RulesGenerator/AGENTS.md` |
| **Automation Tests** | pytest-bdd integration tests | `src/Tests/Automation/AGENTS.md` |
| **Unit Tests** | C++ and eBPF unit tests using Google's GTest | `src/Tests/unit_test/AGENTS.md` |

### README.md files 
Always read README.md files in relevant directories before making changes

---

## Project Structure

```
owLSM/
├── AGENTS.md                    # This file
├── Makefile                     # Main build orchestrator
├── Dockerfile                   # Build environment container
├── README.md                    # Human-readable project documentation
├── Rules/
│   ├── RuleExamples/            # Example security rules in YAML
│   └── RulesGenerator/          # Python rule compiler (YAML → JSON)
├── scripts/                     # Setup, Build and packaging scripts
├── src/
│   ├── Kernel/                  # eBPF programs (*.bpf.c, *.bpf.h)
│   ├── Userspace/               # C++ userspace loader and manager
│   ├── Shared/                  # Common headers for Kernel and Userspace. And other files/scripts needed by different components. 
│   └── Tests/
│       ├── Automation/          # pytest-bdd integration tests
│       └── unit_test/           # Google Test unit tests
├── build/                       # Build output directory
└── docs/                        # Documentation
```

---

## Building the Project

### Environment Setup

Build inside Docker (required for consistent toolchain):

```bash
# Build Docker image (one-time)
docker build -t owlsm-ci-ubuntu18 .

# Start container
docker run -it --rm -v "$PWD":/workspace -w /workspace owlsm-ci-ubuntu18 bash
```

### Build Commands

| Command | Description |
|---------|-------------|
| `make -j$(nproc)` | Build and package owlsm → `build/owlsm/` (bin, lib, resources, rules_generator) |
| `make kernel -j$(nproc)` | Build only eBPF programs |
| `make userspace -j$(nproc)` | Build only userspace (requires kernel) |
| `make test -j$(nproc)` | Build and package unit tests → `build/unit_tests/` (bin, lib) |
| `make tarball -j$(nproc)` | Create release tarball (depends on all) |
| `make automation -j$(nproc)` | Build + setup automation tests (depends on all) |
| `make clean` | Clean all build artifacts |
| `make DEBUG=1 -j$(nproc)` | Debug build |

### Running

```bash
# Exit container first, then run on host (requires root/CAP_BPF)
sudo ./build/owlsm/bin/owlsm
```

---

## Environment Requirements

- **Kernel**: 5.14+
- **libc** 2.32+
- ebpf enabled
- ebpf lsm enabled
- BTF support 
---

## Subdirectory AGENTS.md Files

When instructions in a subdirectory AGENTS.md conflict with this higher level AGENTS.md file, **follow the subdirectory file** (more specific overrides general).

---

## Coding Conventions

### General

- Use comments only on code that is mid/hard to understand
- Always avoid code duplication. 
- Use design patterns when possible.
- Use 3rd party code or libraries instead of inventing the wheel. 
    - In python always try to use existing modules instead writing things from scratch. 
    - In C++ check if there is 3rd party open source project that does it already before implementing from scratch. If you find, ask me if you can use it.
        currently our 3rd party code is at `src/Userspace/3rd_party`

### C/C++ and eBPF
Both userspace C/C++ and kernel EBPF must follow these conventions

#### File/Directory Names
- Underscore separation, all lowercase: `example_file.hpp`
- Extensions: `.cpp`, `.hpp` for C++; `.bpf.c`, `.bpf.h` for eBPF

#### Namespaces
- All lowercase

#### Classes and Structs
- PascalCase: `class ClassName`
- Private members prefixed with `m_`: `m_member_name`
- if a class has no members, make it a static class.

#### Functions
- camelCase: `calculateTotal()`
- Use `const` wherever possible

#### Local Variables
- snake_case, all lowercase: `day_month_year`
- Use `const` and `auto` when possible (but not `auto` for booleans)

#### Added space after if keyword
```C/C++
if (condition)
```

#### Curly Braces
- Always on their own line:
```C/C++
if (condition)
{
    doSomething();
}
```

#### Global Variables
- Constants/macros: ALL_CAPS with underscores: `SYS_FS_BPF_OWLSM_PATH`
- Mutable globals: `g_` prefix: `g_current_state`

#### spliting .hpp and .cpp files.
- If a class has very little code, just use a .hpp file. But if it has more then a little content, split it to .hpp and .cpp files.

#### C++ friend keyword 
- When unit tests classes need to access private methods and members of the tested classes, use the friend keyword.
- Don't use it for anything else

#### Modern C++ code
- When writing C++ code, try to use modern C++ code. Avoid using raw C-style pointers, arrays, etc'. Use these only when necessery.

#### including headers
- If its header files I created do `#include "header_name.hpp"` else do `#include <header_name.hpp>`

#### Code example:
```
// example_user_manager.hpp
#pragma once

#include "car.hpp"
#include <vector>

constexpr int MAX_USER_NAME_LENGTH = 64;
inline int g_active_user_count = 0;

class UserManagerTest;

namespace owlsm::user_management
{

class UserManager
{
public:
    UserManager(const std::string& config_path);
    
private:
    bool validateUser(const User& user) const;

    std::vector<User> m_users;
    
    friend class ::UserManagerTest;
};
}
```

### Python

#### Classes
- PascalCase: `class ClassName`
- Private members prefixed with `_`: `_private_member`
- Non-private members: underscore separation: `public_member`

#### Functions
- Underscore separation: `is_bigger_than()`

#### Local Variables
- Underscore separation: `day_month_year`

#### Global Variables
- ALL_CAPS with underscores: `MAX_NEEDLE_LENGTH`