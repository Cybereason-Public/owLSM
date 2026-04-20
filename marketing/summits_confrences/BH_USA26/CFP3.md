# Title
The Linux Blind Spot: Stopping Shell Built-ins with eBPF

# Tracks
Defense & Resilience; Threat Hunting & Incident Response

# Format
30-Minute Briefings

# Abstract
A surprising amount of Linux attack surface hides inside the shell. An attacker does not need a custom binary to add an SSH key, create a user, stage persistence, or tamper with critical files. `echo`, redirections, `source`, and other shell built-ins are often enough. The problem for defenders is that built-ins do not behave like normal programs. Process telemetry sees `bash`. File monitoring sees a write to `/etc/passwd`. Neither tells you, before the write happens, whether the shell is printing a harmless string or executing a malicious command.

This talk shows how we closed that gap with a stateful Linux prevention design built on extended Berkeley Packet Filter (eBPF) Linux Security Module (LSM) hooks. I will walk through how to correlate shell-specific uprobes with enforcement hooks so a rule can reason about the full command, the target object, and the surrounding execution context in one inline decision. I will cover the messy implementation details most writeups skip: supporting bash, zsh, and dash; recovering command strings when symbols are missing; knowing when one shell command ends and the next begins; and expressing those behaviors as Sigma-style rules instead of one-off detection code. I will also compare this approach with the visibility gaps in mainstream Linux tooling and explain where observability stops being enough for defenders and responders.

Attendees will leave with a practical blueprint for detecting and preventing a class of Linux behavior that still slips past many blue teams.

# Presentation Outline - NOTE THE DETAILED OUTLINE
## 1. OPENING SCENARIO: WHY SHELL BUILT-INS ARE STILL A DEFENSIVE BLIND SPOT
Estimated time: 3 minutes

- Real attacker behaviors that do not require custom binaries:
  - `echo "...">> ~/.ssh/authorized_keys`
  - `echo "...">> /etc/passwd`
  - file tampering, persistence, and privilege abuse through redirection and built-ins
- Why built-ins are attractive to attackers.
- Why defenders still miss them even when they have file and process telemetry.
- Why prevention needs the answer before the write lands, not after.

## 2. WHY THE OBVIOUS SOLUTIONS FAIL
Estimated time: 5 minutes

- Shell config hooks and profile files:
  - bypassable
  - inconsistent across shells
- Replacing or wrapping shell binaries:
  - fragile
  - easy to evade
  - operationally painful
- Monitoring only `readline` or a single uprobe:
  - shell-specific
  - not enough for prevention
  - poor support for shells without symbols
- Monitoring only file or Linux Security Module events:
  - sees that a write happened
  - misses the command that caused it
- Short comparison of the visibility defenders get from common Linux tooling today.

## 3. DESIGN REQUIREMENTS FOR INLINE DECISIONS
Estimated time: 3 minutes

- The rule must see command context and target context together.
- The design must preserve state across multiple hooks.
- The solution must work across multiple shells, not just one happy path.
- The decision must happen in time for prevention, with bounded overhead.

## 4. CAPTURING COMMANDS ACROSS BASH, ZSH, AND DASH
Estimated time: 7 minutes

- Choosing the right hook points for each shell.
- Strategy order:
  - exported symbols when available
  - `libdebuginfod` when symbols are missing
  - offline build-ID-to-offset mapping as a fallback
- Why dash is especially painful.
- Reconstructing shell command data structures from user memory for dash.
- Determining when one command ends and the next begins so state stays correct.
- Lessons learned from supporting multiple shells instead of a single demo target.

## 5. CORRELATING SHELL CONTEXT WITH eBPF LSM ENFORCEMENT
Estimated time: 6 minutes

- The event flow:
  - shell uprobe captures command context
  - state is cached
  - LSM hook evaluates the risky operation
  - decision is made inline
  - state is cleared at command completion
- How state is keyed and invalidated safely.
- Why this has to be stateful rather than event-by-event.
- How to avoid false positives by combining command semantics with actual behavior.

## 6. FROM RAW TELEMETRY TO SIGMA-STYLE RULES
Estimated time: 4 minutes

- Why defenders need reusable rule semantics, not one-off handcrafted logic.
- Expressing shell command content, target file, and process context in one rule.
- Example defensive rules for:
  - unauthorized account creation
  - SSH key persistence
  - sensitive file modification from interactive shells
- Why this matters for both prevention and incident response triage.

## 7. DEFENSIVE TAKEAWAYS AND LIMITS
Estimated time: 2 minutes

- What blue teams can adopt from this approach even without adopting the full implementation.
- The operational limits and edge cases defenders should expect.
- Where Linux prevention research still needs more work.

# Problem Statement
Linux defenders still lack a reliable way to make inline decisions about malicious shell built-ins. Existing tooling usually sees either the command string or the dangerous syscall, but not both together at the moment a prevention decision must be made. That leaves defenders with blind spots around common persistence and privilege-abuse techniques that use only built-in shell behavior.

# Audience Takeaways
1. A practical design for capturing shell built-in activity across multiple Linux shells.
2. A reusable pattern for correlating user-space command context with kernel-space enforcement hooks.
3. Concrete rule ideas for detecting and preventing high-value Linux persistence and file-tampering behaviors.

# Research Novelty
The novelty is not simply "we used eBPF." The new part is a stateful defensive design that joins shell-specific command capture with eBPF LSM enforcement in time for prevention, while still being expressive enough for Sigma-style rules. The talk also covers the shell-specific engineering required to support bash, zsh, and dash in a single defensive model.

# Demo Plans
Yes. The briefing can include a short live or recorded demo showing how common Linux telemetry sees a write to a sensitive file but misses the full command context, followed by the same behavior being blocked once shell context and LSM enforcement are correlated. A second demo can show the same defensive logic working across more than one shell.

# Track Alignment
This fits `Defense & Resilience` because the focus is inline Linux prevention, not post-event visibility. It also fits `Threat Hunting & Incident Response` because the same correlated context that enables prevention produces much richer investigative data for shell-based persistence, privilege abuse, and file-tampering activity.
