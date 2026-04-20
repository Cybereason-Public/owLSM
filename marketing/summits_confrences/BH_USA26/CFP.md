# Title
Alpha Penguin: Implementing Sigma Rules Engine inside the Linux kernel

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
Windows has minifilters, MacOs has Endpoint Security Framework and Linux, well what does Linux have?
For decades penguins had no way to defend themselves against ruthless adversaries, as they lacked basic real time protection tools. 
At first the penguins tried monitoring and observability tools, these alerted them of danger, but until they responded it was already to late...
Then They tried Kernel modules, those had a tendancy to crash, hard to maintain and didn't integrate easily with secure boot.
Finally they came up with eBPF LSM. A promising framework for preventing attackers at real time.

Youv'e seen cool projects that implemnted eBPF LSM to offer policy based protection. But were you able to write comprehensive rules that really made you feel any safer?
Were you able to take the standard set of sigma rules and add any of them? Or are you still looking how to specify basic things like substrings and full process cmd in the enforcment policy?