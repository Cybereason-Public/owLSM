# Title
Alpha Penguin: Building a Sigma Rules Engine with eBPF LSM

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
eBPF supplied Linux defenders excellent observability tools, but inline prevention is still far behind. Existing approaches can block a syscall or enforce a static policy, yet they struggle to express the kind of contextual logic defenders already rely on in Sigma rules. Market leading tools lack in their enforcment policies simple features like conditions, substring matching or even full process commandline. The missing piece is not ideas. It is how to make that logic work inside eBPF LSM hooks without losing to verifier limits.

In this talk I will walk through how we built a stateful Sigma rules engine for Linux using eBPF LSM. I will cover the full algorithm chain that made it practical: From converting sigma rules to an AST tree too being the first open source project to implement O(n) substring matching in eBPF. Then I will cover our stateful approach in eBPF of correlating multiple consecutive hooks so a rule can reason about built-in shell commands that were used for an operation or the full exec context that defenders strive for. I will also show where current Linux tooling still drops crucial context, and why prevention requires different design choices than post-event telemetry.

Attendees will leave with concrete patterns they can reuse in their own eBPF work, plus a realistic understanding of what it takes to move Sigma-like logic from user-space detection systems into the kernel.

# Presentation Outline - NOTE THE DETAILED OUTLINE
## 1. THE PROBLEM SPACE AND WHY LINUX STILL LAGS

- What is the difference between monitoring and respondig to inline prevention
- The time and efficienty constraints of inline prevention
- the lack of available data in inline prevention
- What leading market tools offer today.
- Why "block this syscall" is not enough when defenders need behavioral logic.
- Concrete examples that require richer context:
  - malicious shell built-ins
  - full exec visibility across parent, old image, and new image
  - substring and path-based conditions inside enforcement rules

## 2. CONSTRAINTS THAT SHAPE THE ENTIRE DESIGN

- eBPF verifier constraints that directly affect rule-engine design:
  - bounded loops
  - 512-byte stack
  - no recursion
  - predictable memory access
- Lack of data in a single hooking point. The stateles pitfall.
- efficiency constraint for iniline syscalls monitoring.

## 3. FROM SIGMA YAML TO KERNEL-EVALUABLE LOGIC

- Convert Sigma rule to an AST
- Reverse Polish Notation representation of the AST's predicates.
- Tokenizing predicates and operators for fixed-size stack evaluation inside eBPF.
- Building deduplicated tables for strings, predicates, and IP address data.
- How this representation lets complex rule logic run without recursion.
- Reverse Polish Notation evaluation inside the kernel
- Caching trick based on per CPU map and event time. 

## 4. MAKING STRING MATCHING VERIFIER-FRIENDLY

- Why `contains` is far harder than exact, prefix, or suffix matching in eBPF.
- Why naive O(nxm) search is a poor fit for inline kernel evaluation.
- The failed and partial approaches we tried first: Rabin Karp, Trie and tail calls. 
- Final design:
  - precompute the KMP failure data
  - expand it into a full deterministic finite automaton
  - store the flattened transition table in BPF maps
- Result: one bounded loop, O(n) matching, and predictable verifier behavior.
- Tradeoff discussion: memory cost versus algorithm choice.

## 5a. STATEFUL CORRELATION: FROM ISOLATED EVENTS TO DEFENSIVE CONTEXT

- Why a single hook is often not enough to make a correct prevention decision.
- Correlating shell command capture with LSM enforcement hooks.
- Correlating multiple exec-related hooks to recover the full execution story.

## 5b. REAL-WORLD DEFENSIVE USE CASES OF STATEFUL CORRELATION

- Blocking suspicious writes to files like `/etc/passwd` based on corrolation between shell uprobes and LSM hooks.
  - Explainng why this type of fine graine rules aren't possible in the stateless tools
    - Monitoring shell commands alone isn't enough, example of a false positive 
    - Monitoring write syscalls isn't enough, as we can't know what was written and what command generated the behavior.
  - Only by corrolating both hooks we can get the full picture.

## 6. CONCLUSION AND TAKEAWAYS

- The main design patterns that made advanced rule evaluation possible inside eBPF.
- Where current Linux defense stacks still leave gaps.
- What attendees can borrow for their own eBPF-based detection and prevention work, even if they need to build an eBPF defensive tool.
