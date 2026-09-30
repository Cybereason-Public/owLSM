owLSM Kubernetes automation tests. Integration tests that deploy owLSM into a Kubernetes cluster and verify its behavior.  
We use the ***pytest bdd*** as the testing framework.

This suite is separate from `src/Tests/Automation` (Linux). The default developer flow runs against a local **kind** cluster and needs **no secrets or cloud credentials**.

# Prerequisites

On the host: `docker`, `kind`, `kubectl`, `helm`, `uv`.  
The host kernel must support BPF LSM (owLSM runs as a BPF-LSM runtime inside the cluster nodes).

# Setup

```bash
# from the repo root

# 1) Build owLSM for Kubernetes inside the CI container → build/owlsm-k8s/
docker pull ghcr.io/cybereason-public/owlsm-ci:latest
docker run -it --rm -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash

# inside the container:
make K8S=1 -j$(nproc)      # → build/owlsm-k8s/
exit

# 2) Build the owlsm:local runtime image the tests load into kind (run on the host)
docker build -f kubernetes/Dockerfile -t owlsm:local build/owlsm-k8s

# 3) Create a venv and install the requirements
cd src/Tests/K8S_Automation
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt
```

# Run tests

pytest creates the kind cluster, loads `owlsm:local`, deploys owLSM with Helm from `kubernetes/chart/`, runs the scenarios, then deletes the cluster. No secrets required.

Run all the tests
```bash
# Run as root
export AUTOMATION_ROOT_DIR=$(pwd)
PYTHONPATH=$AUTOMATION_ROOT_DIR pytest features/ -v -s
```

Run a single test
```bash
# Run as root
export AUTOMATION_ROOT_DIR=$(pwd)
PYTHONPATH=$AUTOMATION_ROOT_DIR pytest features/all_test.py::test_host_chmod_event -v -s
```

Defaults are `OWLSM_CLUSTER_TYPE=kind`, `OWLSM_IMAGE_REPOSITORY=owlsm`, `OWLSM_IMAGE_TAG=local`, so the commands above need no extra environment. Override those variables only if you want a different image or the `oci` cluster type (CI-only; requires OKE credentials).

### debugging the tests:
1) Install the following extensions in your editor:  
Python Debugger  
Cucumber (Gherkin) Full Support  
Python  
Python Test Explorer for Visual Studio Code  
Test Explorer UI  
Test Adapter Converter  
2) Move to the "Test Explorer", right click on the test you want to debug and select debug.

# Important logs
**automation.log** — the test framework logger (`Utils/logger_utils.py`).  
**owLSM_output.log** — owLSM container stdout, captured via `kubectl logs`.  
**owlsm.log** — owLSM logger, copied from the host mount with `kubectl cp`.
