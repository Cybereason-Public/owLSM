# Title
Alpha Penguin: Building a Sigma Rules Engine with eBPF LSM

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
eBPF gave defenders excellent observability, but inline prevention still lags behind. Existing approaches can block a syscall or enforce a basic policy, yet they struggle to express the kind of contextual logic defenders already rely on in Sigma rules. Even market leading tools still miss simple but important things like conditions, substring matching, or the full process command line in their enforcment policies. The problem is not a lack of ideas. The problem is making that logic work inside eBPF LSM hooks without losing to verifier limits.

In this talk I will walk through how we built a stateful Sigma rules engine using eBPF LSM. I will cover the algorithm chain that made it practical, from converting Sigma rules into an AST to implementing the first open source O(n) substring matcher for eBPF. Then I will show the stateful side of the design: correlating multiple hooks so a rule can reason about the shell command that led to a syscall, or the full context of an exec (including the parent process, old image and new image). I will also show where leading solutions still miss crucial context, and why prevention requires different design choices than post-event telemetry.
We are the first open source project to implement each concept this talk covers.

Attendees will leave with practical design patterns they can reuse in their own eBPF work, a better understanding of how to chain eBPF hooks and correlate data across them, and a clearer view of what it really takes to move Sigma-style logic into the kernel.

# Presentation Outline - NOTE THE DETAILED OUTLINE
## 1. WHY INLINE PREVENTION ON LINUX STILL LAGS
Estimated time in minutes: 3

Linux defenders do not lack telemetry, but telemetry is not the same as prevention. I will open by framing the difference between monitoring an operation after the fact and making a reliable inline decision before it happens. This section will cover the timing and efficiency constraints that make prevention difficult, the limited context available at enforcement time, and the narrow policy model most current Linux tools still expose.

## 2. CONSTRAINTS THAT SHAPE THE ENTIRE DESIGN
Estimated time in minutes: 4

Before getting into the engine itself, I will explain the verifier constraints that shaped every design choice: bounded loops, stack limits, and no recursion. Just as important, a single LSM hook rarely carries enough reliable data for a high-confidence decision. This section sets up why the obvious approach of "just evaluate the rule in the hook" falls apart quickly, and why both algorithm choice and hook correlation become central to the design.
On top of that, every design choice must account for efficiency, as we are inspectig syscalls inline.

## 3. FROM SIGMA YAML TO KERNEL-EVALUABLE LOGIC
Estimated time in minutes: 8

This part of the talk walks through the rule-compilation pipeline. I will show how a Sigma rule moves from YAML into an AST, how that tree is converted into Reverse Polish Notation, and how predicates and operators are tokenized for fixed-size stack evaluation before being passed to the kernel. The focus here is not only on the individual steps, but on why this representation works well inside eBPF: it avoids recursion, keeps evaluation linear, and makes complex rule logic practical under verifier constraints.
The full algorithm chain is:
1. Convert the Sigma rule into an AST.
2. Convert the AST into a Reverse Polish Notation representation.
3. Tokenize predicates and operators for fixed-size stack evaluation inside eBPF.
4. Build deduplicated tables for strings, predicates, and IP address data.
5. Serialize everything and pass it to the kernel.
6. Evaluate the logic in a way that avoids recursion and stays verifier-friendly. Short-circuiting Polish notation evaluation.
7. Use O(n) Reverse Polish Notation evaluation in the kernel, backed by custom stacks and a per-CPU cache tied to event time.

## 4. MAKING STRING MATCHING VERIFIER-FRIENDLY
Estimated time in minutes: 5

One of the most obvious gaps in current tools is substring matching. Exact, prefix, and suffix checks are manageable in eBPF, but a `contains` operation is far more complicated due to verifier limitations. In this section, I will briefly cover the approaches that did not hold up well enough, including Rabin-Karp, Trie, and tail-call-heavy designs, before walking through the approach that worked: precomputing KMP failure data, expanding it into a deterministic finite automaton, and storing the flattened transition table in BPF maps. The result is the first open source O(n) substring mechanism implemented in eBPF.

## 5. STATEFUL CORRELATION: TURNING ISOLATED HOOKS INTO DEFENSIVE CONTEXT
Estimated time in minutes: 6

This section covers the part that matters most for real prevention: state. I will show why the common single-LSM-hook approach cannot answer questions like "what shell command actually caused this syscall?" or "what is the full execution story behind this exec?" Then I will walk through two concrete defensive examples. The first correlates a shell uprobe with an LSM hook so defenders can block syscalls based on the command that produced them. The second shows how we reconstruct meaningful exec context by combining three different LSM hooks so a rule can reason about the parent process, the old image, and the new image together.

## 6. WHAT THIS CHANGES FOR DEFENDERS
Estimated time in minutes: 4

I will close by comparing this approach with the gaps in today's Linux prevention tooling and by distilling the patterns attendees can reuse in their own work. The larger point is that many of the limits people accept as "just how eBPF works" are really design problems. With the right algorithms and a stateful model, significantly richer prevention logic becomes possible without giving up verifier safety.

# Problem Statement
eBPF observability tools are amazing, but market leading eBPF enforcment solutions are almost useless. 
They are stateless, thus missing crucial context in each hook.
They surrendered to the eBPF verifier. So they don't offer "complex" options like the contains modifier.
They are non-conditional, we can't specify complex condition in the rule.
They are missing many needed sigma features like: keywords, fieldref, |all, etc'

Its time to change it, and create a full stateful Sigma Rules Engine with eBPF LSM

# Audience Takeaways
Attendees will leave with a concrete model for translating Sigma rule logic into verifier-friendly eBPF evaluation, a practical design pattern for carrying state across hooks when one event is not enough, and several reusable ideas for building Linux prevention logic that goes beyond static policy checks.

# Research Novelty
The novelty here is not simply using eBPF LSM. It is showing how to make Sigma rule semantics practical inside verifier-constrained kernel enforcement by combining many algorithms and corrolating data between eBPF hooks to create a stateful rules engine. This is the first open source implementation of any of these concepts. 

# Demo Plans
Yes. The briefing can include a short demo that compares what common Linux telemetry sees during a malicious shell-built-in workflow with what a stateful correlated design can see and block inline. A second demo can show how multi-hook exec correlation exposes context that a single hook cannot provide.

# Track Alignment
This submission fits `Defense & Resilience` because it is focused on inline protection design for Linux, not just observability. It also fits `Threat Hunting & Incident Response` because the same correlated context that improves prevention also produces much better investigative context for shell-based abuse and suspicious exec activity.
