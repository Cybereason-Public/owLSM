# Title
Alpha Penguin: Building a Sigma Rules Engine with eBPF LSM

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
Linux defenders have excellent observability tools, but inline prevention is still far behind. Most existing approaches can block a syscall or enforce a static policy, yet they struggle to express the kind of contextual logic defenders already rely on in Sigma rules: substring matching, full shell commands, multi-step process context, and state carried across related events. The missing piece is not ideas. It is how to make that logic work inside extended Berkeley Packet Filter (eBPF) Linux Security Module (LSM) hooks without losing to verifier limits, tiny stacks, no recursion, and strict performance requirements on the syscall path.

In this talk I will walk through how we built a stateful Sigma-style rules engine for Linux using eBPF LSM. I will cover the full algorithm chain that made it practical: parsing detection logic in userspace, compiling nested conditions into postfix notation for stack-based kernel evaluation, implementing verifier-friendly O(n) substring matching through a precomputed Knuth-Morris-Pratt (KMP) deterministic finite automaton (DFA), and correlating multiple hooks so a rule can reason about shell commands and full exec context instead of isolated syscalls. I will also show where current Linux tooling still drops crucial context, and why prevention requires different design choices than post-event telemetry.

Attendees will leave with concrete patterns they can reuse in their own eBPF work, plus a realistic understanding of what it takes to move Sigma-like logic from user-space detection systems into the kernel.

# Presentation Outline - NOTE THE DETAILED OUTLINE
## 1. THE PROBLEM SPACE AND WHY LINUX STILL LAGS
Estimated time: 4 minutes

- What defenders get today on Windows and macOS versus Linux.
- Why "block this syscall" is not enough when defenders need behavioral logic.
- Concrete examples that require richer context:
  - malicious shell built-ins
  - full exec visibility across parent, old image, and new image
  - substring and path-based conditions inside enforcement rules
- Short comparison of current Linux approaches: strong telemetry, limited inline rule semantics.

## 2. CONSTRAINTS THAT SHAPE THE ENTIRE DESIGN
Estimated time: 5 minutes

- eBPF verifier constraints that directly affect rule-engine design:
  - bounded loops
  - 512-byte stack
  - no recursion
  - predictable memory access
- Why naive AST walking does not fit.
- Why naive substring search becomes verifier-hostile.
- Why stateless policy engines cannot express many useful defensive rules.
- The functional and performance requirements for a kernel-resident Sigma-style engine.

## 3. FROM SIGMA YAML TO KERNEL-EVALUABLE LOGIC
Estimated time: 8 minutes

- Using pySigma to parse detection logic into an abstract syntax tree (AST).
- Converting nested boolean expressions into postfix / Reverse Polish Notation.
- Tokenizing predicates and operators for fixed-size stack evaluation inside eBPF.
- Building deduplicated tables for strings, predicates, and IP address data.
- Why deduplication matters for both memory usage and predicate caching.
- How this representation lets complex rule logic run without recursion.

## 4. MAKING STRING MATCHING VERIFIER-FRIENDLY
Estimated time: 5 minutes

- Why `contains` is far harder than exact, prefix, or suffix matching in eBPF.
- Why naive O(nxm) search is a poor fit for inline kernel evaluation.
- The failed and partial approaches we tried first.
- Final design:
  - precompute the KMP failure data in userspace
  - expand it into a full deterministic finite automaton
  - store the flattened transition table in BPF maps
- Result: one bounded loop, O(n) matching, and predictable verifier behavior.
- Tradeoff discussion: memory cost versus reliable inline execution.

## 5. STATEFUL CORRELATION: FROM ISOLATED EVENTS TO DEFENSIVE CONTEXT
Estimated time: 6 minutes

- Why a single hook is often not enough to make a correct prevention decision.
- Correlating shell command capture with Linux Security Module enforcement hooks.
- Correlating multiple exec-related hooks to recover the full execution story.
- How predicate-result caching avoids repeated work during one event evaluation.
- Example Sigma-style rules that only become practical once state is preserved across hooks.

## 6. REAL-WORLD DEFENSIVE USE CASES
Estimated time: 2 minutes

- Blocking suspicious writes to files like `/etc/passwd` based on both target and command context.
- Distinguishing a malicious shell action from a harmless string print.
- Using the same rule semantics for prevention and richer incident-response context.

## 7. CONCLUSION AND TAKEAWAYS
Estimated time: 2 minutes

- The main design patterns that made advanced rule evaluation possible inside eBPF.
- Where current Linux defense stacks still leave gaps.
- What attendees can borrow for their own eBPF-based detection and prevention work, even if they never build a full rules engine.
