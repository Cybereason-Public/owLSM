# AGENTS.md - K8S Automation Tests

## Overview

Kubernetes integration tests for owLSM using pytest-bdd. This is a separate suite from `src/Tests/Automation` (Linux). Tests run against a cluster with kubectl, Helm, and SSH.

## Project Structure

```
K8S_Automation/
├── AGENTS.md            # This file
├── pytest.ini           # pytest settings
├── requirements.txt     # Python dependencies
├── conftest.py          # session/scenario hooks
├── features/            # Gherkin features + all_test.py (pytest-bdd scenario bindings)
├── steps/               # pytest-bdd step definitions
├── globals/             # GlobalStrings, GlobalObjects, GlobalNumbers
└── Utils/               # cluster, owlsm, file, log, logger helpers
```

## Tech Stack

- **Python 3.10+**
- **pytest** / **pytest-bdd**
- **uv** for the venv

## How to run

See [README.md](README.md) for the full local build-and-run flow (kind, no secrets), including how to run a single test.

## Important notes

- Do not mix this suite with `src/Tests/Automation`. They are completely seperate.
- Deploy owlsm with Helm from `kubernetes/chart/` on disk.
- Default image is owlsm:local (kind load on kind). If OWLSM_IMAGE_REPOSITORY is GHCR (CI), skip kind load and pull test-owlsm-runtime. Tests never install owlsm-runtime:vX.Y.Z.
- OWLSM_CLUSTER_TYPE: kind (default; pytest creates/deletes the cluster) vs oci (kubeconfig already on the controller vm;
- controller vm is the VM that controls the cluster. Pytest and GH runner runs on the controller VM.

## Log files

- `automation.log` — test framework logger (`Utils/logger_utils.py`)
- `owLSM_output.log` — owlsm container stdout (via `kubectl logs`)
- `owlsm.log` — owlsm logger copied from the host mount with `kubectl cp`
