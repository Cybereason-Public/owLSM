<p align="center">
  <img width="525" height="150" alt="owLSM_logo-Photoroom" src="docs/owLSM_logo-Photoroom.png" />
  <br><br>
  🛡️ <i>owLSM aspires to become the gold standard for prevention and detection for Linux</i> 🛡️
  <br><br>
  <a href="https://cybereason-public.github.io/owLSM/"><img src="https://img.shields.io/badge/Docs-GitHub%20Pages-blue?style=flat-square&logo=github" alt="Docs"></a>
  <a href="https://discord.gg/gQk5Jxd6vs"><img src="https://img.shields.io/discord/1467824033188941952?label=Discord&logo=discord&style=flat-square" alt="Discord"></a>
  <a href="AGENTS.md"><img src="https://img.shields.io/badge/AI%20Agents-Friendly-blueviolet?style=flat-square" alt="Agent Friendly"></a>
  <a href="https://github.com/Cybereason-Public/owLSM/actions/runs/23287577166"><img src="https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square" alt="CI passing"></a>
</p>

owLSM is an eBPF LSM agent that implements a stateful Sigma rules engine focused on prevention.

<p>
<b><span style="font-size:1.15em">What is the project:</span></b> owLSM focuses on three main things:<br>
1) Prevention capabilities using a Sigma Rules Engine implemented via eBPF LSM.<br>
2) Data correlation between eBPF probes for stateful prevention capabilities.<br>
3) Security-focused system monitoring where each event contains all the context a security expert needs.
</p>

<p>
<b><span style="font-size:1.15em">Who is it for:</span></b> Teams that defend Linux systems, companies offering Linux/Cloud security solutions, and developers or agents looking for implementation examples of complex eBPF solutions.
</p>

<p>
<b><span style="font-size:1.15em">Where is it already being used:</span></b> Customers of the security firms Cybereason and LevelBlue.
</p>

<p>
<b><span style="font-size:1.15em">Why we created this project:</span></b> After years of using projects like Falco, Tetragon, and KubeArmor, we kept running into the same gaps. These solutions offer little to no prevention (enforcement) capabilities. Those that do offer enforcement policies lack basic features like substring matching, full process command line access, and parent termination of malicious processes.<br>
We decided to take a completely different approach:<br>
1) Use the standard Sigma rules structure and support as many Sigma rules features as possible (constantly adding more).<br>
2) Solve the core limitation of current eBPF LSM projects: they are stateless. Almost all data available in an enforcement rule comes only from the current hook.<br>
We created stateful eBPF programs that use multiple consecutive hook points and correlate data between them, so at the point of the prevention decision, users have all the data they need. We took this stateful approach so far that, for example, when monitoring write events, you can specify prevention rules based on the shell command that initiated the write.
</p><br>

Help us grow and protect the world by giving us a ⭐ 
 <br>
> **Cloud support will come in the future**


## How to build

```bash
# Build the Docker image (one-time setup):
docker build -t owlsm-ci-ubuntu20 .

# Start the build container
docker run -it --rm -v "$PWD":/workspace -w /workspace owlsm-ci-ubuntu20 bash

# Build owLSM
make -j$(nproc)

# Build unit tests
make test -j$(nproc)

# Exit container, can't run owlsm or the tests inside the docker
exit
```

## Run owLSM

Do this outside the docker
```bash
cd build/owlsm/bin

# run without config 
sudo ./owlsm 

# run with config 
sudo ./owlsm -c /config/path.json

# run with config and excluded pid's (usually we want to exclude parent processes)
sudo ./owlsm -c /path/to/config.json -e 123 -e 456
```

> **Note:** owLSM Startup takes **10–50 seconds** depending on the system. This is the eBPF verifier validating all programs before they are loaded into the kernel. Once complete, owLSM is fully active.

## Config and rules
See [Rules/README.md](Rules/README.md)

## Run Unit Tests

```bash
cd build/unit_tests/bin

# Run the unit tests
sudo ./unit_tests
```

## Check Compatibility

Before running owLSM, verify your system meets the requirements:

```bash
chmod +x scripts/check_compatibility.sh && ./scripts/check_compatibility.sh
```

## Automation Tests (Integration Testing)
See [src/Tests/Automation/README.md](src/Tests/Automation/README.md) for running the automation tests.

# Join the community 
To get involved with the owLSM project visit our [discord](https://discord.gg/gQk5Jxd6vs).  
If you have any questions please ask them on the discord or open a relevant issue.

📖 Visit the [documentation](https://cybereason-public.github.io/owLSM/) for everything you need — how to use the project, write rules, understand the architecture, and more.

## Contributers 
We're thrilled that you're interested in contributing to owLSM!  
Please check [CONTRIBUTING.md](.github/CONTRIBUTING.md) to know about the rules, conventions and even **cool AI tools and agents** that will help you a lot!

## License

owLSM is licensed under the **GNU General Public License v2.0** (GPL-2.0).

### Third-Party Libraries

This project includes several third-party libraries with their own licenses
(all GPL-compatible). See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for
details.
