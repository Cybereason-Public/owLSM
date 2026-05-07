---
layout: default
title: Artifacts
nav_order: 7
permalink: /artifacts/
---

# Artifacts

How owLSM build outputs are organized — both during development (`build/`) and in the release tarball.

---

## Build Output (`make`)

Running `make -j$(nproc)` builds and packages into `build/owlsm/`:

```
build/owlsm/
├── bin/
│   ├── owlsm                  # Main binary
│   └── rules_generator        # RulesGenerator binary
├── lib/
│   ├── libelf.so.1            # Required shared libraries
│   ├── libz.so.1              # (auto-detected via ldd)
│   └── ...
└── resources/
    ├── base_config.json       # Starting config template (no rules)
    └── ...                    # Userspace resource files
```

## Unit Tests Output (`make test`)

Running `make test -j$(nproc)` builds and packages into `build/unit_tests/`:

```
build/unit_tests/
├── bin/
│   └── unit_tests             # Google Test binary
└── lib/
    └── ...                    # Required shared libraries
```

## Release Tarball (`make tarball`)

Running `make tarball -j$(nproc)` creates `build/owlsm-{VERSION}.tar.gz` containing the same layout as `build/owlsm/`.

The tarball is a self-contained distribution: the `lib/` directory includes all non-system shared libraries needed to run `owlsm` on the target machine, so no additional library installation is required beyond basic libs like glibc and the [system requirements](/owLSM/getting-started/).

---