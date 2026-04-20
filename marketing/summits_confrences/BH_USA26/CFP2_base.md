# Title
Alpha Penguin: Implementing Sigma Rules Engine inside the Linux kernel

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
The higher the expectation the greater the disappointment. This what many felt about eBPF LSM.
the framework that prommised to finally offer safe and scalable real time prevention capabilities for Linux after decades of kernel modules and observability tools.
However, the eBPF verifier made it hard to implement great prevention tools. 

Youve seen the leading projects that used eBPF LSM to offer policy based prevention.
Were you able to create any useful rules? Were you able to import basic sigma rules into these tools? Probably not. Due to the eBPF verifier limitations, the current solutions weren't able to implement very basic features like substring matching or full process cmd.
Its time change this and finally start using eBPF LSM as Linus would want us to. 

This talk will present eBPF tricks, algorithms and out of the box thinking that allowed us to implement the first of its kind: stateful Sigma Rules Engine via eBPF LSM.
We will go through several concept that we used, so you will be able to use them as well next time you use eBPF. 


# Presentation Outline – NOTE THE DETAILED OUTLINE
## 1. INTRODUCTION
- What are sigma rules
- What is eBPF LSM and verifier limitations  (loop, stack size, recursion)

## 2. Algorithms 
### 2.1 KMP DFA to implement verifier friendly O(n) substring. We are the first to do it. 
See full data in marketing/content/Reddit/substring_kmp_full.md

### 2.2 Full algorithm flow of AST-> postfix -> tokenazation -> reverse polish interpretion with stacks.
See full data in marketing/content/Reddit/rule_flow

## 3. Shell built in commands and shell monitoring
- How we monitors different shells
- How we corrolate between monitored syscalls and commands, to allow users to prevent operations based on the command. Show example.
- Why the stateful approch is needed.
See full data in marketing/content/shell_builtit.md  and  docs/GithubPages/architecture/shell-commands.md
- Other eBPF LSM solutions lack this. 

## 4. Exec Monitoring
- How we monitor 3 different hooks in order to get the full exec picture (parent process, old process, new process)
- Why we listen to open as the final hook of the exec flow (it will try to load .so files, and fail and the process will die. If its a fully static binary we can replace open with brk/mmap)
    + show that strace ensures us that it will always try to open .so files before running malicious code. 
- Other eBPF LSM solutions lack this. So we can't have a full picture of an exec at the prevention rule level.


## 5. CONCLUSION & TAKEAWAYS
- designing a correct algorithm chain can solve verifier isseus 
- using a chain of probes to represent a prevention hook, allows us to create stateful preventions with all the data users need.