owLSM automation tests. Test different components of the owLSM.  
We use the ***pytest bdd*** as the testing framework  

# Setup

```bash
# from the root directory 
# start the docker
docker pull ghcr.io/cybereason-public/owlsm-ci:latest
docker run -it --rm -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash

# Build owLSM
make -j$(nproc)

# Build automation 
make automation -j$(nproc)

# exit docker
exit

# create a venv and install the requirements
cd src/Tests/Automation
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt
```

# Run tests

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
PYTHONPATH=$AUTOMATION_ROOT_DIR pytest features/all_test.py::test_name -v -s
```
### debugging the tests:
1) Install the following extensions in your cursor:  
Python Debugger 
Cucumber (Gherkin) Full Support  
Python  
Python Test Explorer for Visual Studio Code  
Test Explorer UI  
Test Adapter Converter  
2) Move to the "Test Explorer" in vscode. Right click on the test you want to debug and select debug.

# Important logs
**automation.log** - The automation log. This is created by the automatioan.  
**owLSM_output.log** - The owLSM events log. owLSM prints the events to stdout and the automation redirects it to this file.  
**owlsm.log** - owLSM logger creates this file next to the binary and writes directly to it.  