# Title
Alpha Penguin: Building a Sigma Rules Engine with eBPF LSM

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
eBPF supplied Linux defenders excellent observability tools, but inline prevention is still far behind. Existing approaches can block a syscall or enforce a static policy, yet they struggle to express the kind of contextual logic defenders already rely on in Sigma rules. Market leading tools enforcment policies lack simple features like conditions, substring matching or even full process commandline. The missing pieces are not ideas. It is how to make that logic work inside eBPF LSM hooks without losing to verifier limits.

In this talk I will walk through how we built a stateful Sigma rules engine for Linux using eBPF LSM. I will cover the full algorithm chain that made it practical: From converting sigma rules into an AST tree, to being the first open source project to implement O(n) substring matching in eBPF. Then I will cover our stateful approach in eBPF of correlating multiple consecutive hooks so a rule can reason about shell commands that initiated the malicious syscall or the full exec context that defenders strive for. I will also show where Market leading solutions miss crucial context, and why prevention requires different design choices than post-event telemetry.
We are the first open source project to implement each concept this talk covers

Attendees will leave with concrete patterns they can reuse in their own eBPF work, plus a realistic understanding of what it takes to move Sigma-like logic from user-space detection systems into the kernel.

# Presentation Outline - NOTE THE DETAILED OUTLINE

## 1. INTRODUCTION
Estimated time in minutes: 2

- What is eBPF and eBPF LSM
- What are sigma rules


## 2. What is inline prevention
Estimated time in minutes: 3

What is the difference between monitoring + respondig to inline prevention
- The time and efficienty constraints of inline prevention
- In order to prevent we must use eBPF LSM. However, A single LSM hook doesn't provide all the data, the relevant context is split across multiple hooks. Unlike tracing hooks that occur after the operation and hold much more data. 
  Later I show an example of how little data an LSM hook provides, against a tracing hook. 

## 3. gaps in current market leading solutions
Estimated time in minutes: 5

What market leading tools enforcment policies offer
  - How stateless are their rules: can't use any data that isn't achivable in the current hook.
    Thus their basic "block this syscall" rule isn't very helpful as users can't specify important data. 
    Here I will show a few examples of Tetragon rules, and show how lean they are. 
  - List of sigma rules features, that they are missing: substring, fieldref, keyword, conditions, regex, etc'

Concrete examples of rules you desire to have but can't write with current tool:
  - rule that blocks a malicious shell built-in write due to the corrolation between shell monitoring and the write LSM hook.
  - rule that blocks exec event due to all of: parent process, old image and new image.
  - rules that use substring and full process commadline

## 4. CONSTRAINTS THAT SHAPE THE ENTIRE DESIGN
Estimated time in minutes: 2

eBPF verifier constraints that directly affect rule-engine design:
  - Max number of instructions
  - bounded loops
  - 512-byte stack
  - no recursion

Lack of data in a single hooking point. The stateles pitfall.
  - What data can you get from the `lsm/path_chmod` hook? Show an example of how little data I can get in the hook. And this isn't enough for rules.
  - Is the data even reliable? For example `task->real_parent` isn't always the real parent process.


## 5. FROM SIGMA YAML TO KERNEL-EVALUABLE LOGIC
Estimated time in minutes: 8

Our goal is to evaluate complex sigma rules at runtime in eBPF LSM in order to prevent malicious operations.
For that we need to use a long chain of algorithms that will allow us to do it in an efficient and verifier friendly way.
Here is the order of the algorithms

1. Convert Sigma rule to an AST
2. Convert the AST nodes to Reverse Polish Notation representation.
3. Tokenizing predicates and operators for fixed-size stack evaluation inside eBPF.
4. Building deduplicated tables for strings, predicates, and IP address data.
5. Serializing everything and passing it to the kernel.
6. How this representation lets complex rule logic run without recursion.
7. O(n) Reverse Polish Notation evaluation inside the kernel, using self-implemented stacks.
8. Caching trick based on per CPU map and event time. 

## 6. MAKING STRING MATCHING VERIFIER-FRIENDLY
Estimated time in minutes: 5

- Why string contains is far harder than exact, prefix, or suffix matching in eBPF.
- Why naive O(nxm) search is a poor fit for inline kernel evaluation.
- The failed and partial successfull approaches we tried first: Rabin Karp, Trie and tail calls. 

Final design:
  - precompute the KMP failure data
  - expand it into a full deterministic finite automaton
  - store the flattened transition table in BPF maps

Result: one bounded loop, O(n) matching, and predictable verifier behavior.

## 7. STATEFUL CORRELATION for real exec prevention
Estimated time in minutes: 3

An example to a basic scenario where the stateful approch is requiered is the prevention of malicious exec.
When an exec happens, there are 3 important objects: parent process, old image and new image
However, their isn't any eBPF LSM hook that you can get all the data from.
This requieres us to create an abstract statefull hook, that combines 3 different eBPF LSM hooks.
Only with these 3 hooks we can build the full picture and provide the user the capability to specify any of these 3 processes in the rules. 


## 8. CONCLUSION AND TAKEAWAYS
Estimated time in minutes: 2

- Stateful approch is required for having the full context at the prevention desicion.
- The main algorithms that made advanced rule evaluation possible inside eBPF.
- Everything is possible in eBPF, you just need to find the correct algorithm.
