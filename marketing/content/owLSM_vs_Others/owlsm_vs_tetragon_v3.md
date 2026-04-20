# Follow-up: your “what I understand” + Q&A (vs Tetragon v1.6.1)

This document answers the questions in your notes and checks whether your three bullet “summary” statements are accurate.

References are pinned to **Tetragon v1.6.1** where it matters:

- Selectors / actions: `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/docs/content/en/docs/concepts/tracing-policy/selectors.md`
- `KProbeSelector` CRD shape: `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/pkg/k8s/apis/cilium.io/v1alpha1/types.go`

---

## Part A — Is your “what I understand” correct?

### 1) “Tetragon doesn’t support substring matching (string contains)”

**Mostly correct, with one nuance.**

For typical string arguments in `matchArgs` / `matchData`, the documented operators include exact / set-style matching and **prefix / postfix** style matching (see the “Operator types” section in v1.6.1 `selectors.md`). Prefix/postfix are **not** the same as an arbitrary infix “contains” / substring-anywhere predicate.

So: if by “substring” you mean **general contains**, your statement is right. If you mean “any non-exact string match”, it is too strong (prefix/postfix exist).

### 2) “Tetragon doesn’t support regex”

**Correct for the documented in-kernel selector operators** in v1.6.1 `selectors.md` (no regex operator in that operator list).

Separate note: you can always regex in **userspace** on exported events; that is outside the “enforcement selector in the kernel” scope you care about.

### 3) “v1.6.1 has no `matchParentBinaries`, therefore enforcement only sees `task.real_parent`, so reparenting breaks parent matching”

**This chain is not reliable; the middle step is the weak link.**

- **True:** In v1.6.1 `types.go`, `KProbeSelector` includes `matchPIDs`, `matchArgs`, `matchData`, `matchBinaries`, etc., and **does not** include `matchParentBinaries` (that selector name appears in newer upstream docs/CRDs, but not in this tag’s `KProbeSelector`).
- **Not established (and likely wrong as a blanket statement):** That the kernel enforcement path “only” consults `task->real_parent` for parent semantics. Tetragon maintains process/exec metadata in BPF (for example the `execve_map` machinery described in v1.6.1 `bpf/lib/process.h`, including a parent key field `pkey` carried alongside the current process entry). Exported events also carry stable identifiers (`exec_id`, `parent_exec_id`, etc. in the API docs).

What you *can* say safely for v1.6.1:

- You **cannot** express “parent executable must match X” as a **first-class** `matchParentBinaries`-style selector on that tag (because it is not in the v1.6.1 CRD struct shown above).
- Parent/reparenting stories are still **subtle**: there are real edge cases around reconstruction (Tetragon’s own API docs discuss flags like `taskWalk` / `miss` around parent info), but that is **not** the same as a proof that enforcement always tracks `task.real_parent` only.

If your article needs one sentence: **“v1.6.1 doesn’t expose parent-binary matching in `KProbeSelector`; parent lineage is still tracked for events, but expressing parent-based enforcement compactly is limited compared to owLSM’s model.”**

---

## Part B — Your questions

### 1) Is Tetragon’s `resolve` flag equal to owLSM `fieldref`? Is `resolve` worse?

**No — same high-level idea (“get more data than the raw parameter”), different mechanism and different expressiveness.**

- **owLSM `|fieldref` (Sigma-side):** compares **two named fields in the product’s event schema** at rule evaluation time (example pattern: `process.file.filename|fieldref: parent_process.file.filename` in your RulesGenerator tests). It is explicitly **relational**: field A vs field B on the same logical event object graph.

- **Tetragon `resolve`:** walks from a **hooked kernel argument** (a typed object like `struct linux_binprm *`, `struct file *`, etc.) along a configured path to materialize an additional scalar-ish value into the tracing argument pipeline. It is **struct projection**, not “compare arbitrary field A to arbitrary field B in the rule DSL”.

So `resolve` is not “less good”; it is **answering a different question**. For “compare two fields of the final event object”, Sigma+owLSM fieldref is closer to what you want in prose. For “reach into a kernel object to expose `mm.owner...` style fields without writing a custom hook”, `resolve` is the Tetragon tool — with the documented kernel-version limitations in the hooks docs (kprobe vs LSM vs uprobe caveats appear there).

### 2) How are selectors related to Sigma’s `condition`? OR only? AND only by merging?

**Your mental model is close to v1.6.1’s documented semantics, with one important detail about actions.**

From v1.6.1 `selectors.md` (early section):

- **Inside one selector:** all listed filters are **AND**ed (“for a selector to match, all of its filters must match”).
- **Across selectors on the same hook:** multiple selectors behave like **disjunction** (“OR”), and the doc states the **first matching selector wins** for which action runs (short-circuiting).

So:

- If you need “A AND B AND C” across what would naturally be separate concerns, you typically **put them in the same selector** (your “merge” intuition).
- If you need “(A AND B) OR (C AND D)”, you can often model it as **two selectors**, each internally ANDed — **but** you must remember the **first-match wins** rule for actions if both could match (ordering matters).

You are also right that this is **not** an arbitrary boolean DSL with free parentheses, `1 of`, etc., like rich Sigma `condition` trees. `selectorsMacros` helps reuse fragments, but it does not turn TracingPolicy into a full logic engine.

### 3) What is the relation between `matchArgs` and full process CMD for **prevention**? Did I misunderstand?

**You did not miss a hidden “full argv” `matchArgs` — your prevention-focused reading is basically right.**

Clarifying the earlier feedback:

- **`matchArgs` is tied to the hooked function’s formal arguments** (by `index` / `args` mapping in the policy). For a syscall hook, that might include individual string arguments that are *pieces* of a command line, but it is still “arguments of this hook”, not owLSM’s **`process.cmd` as one merged command line string** used consistently across semantic events.
- **Full command line as a single string** is visible in **exported event JSON** as `process.arguments` in many examples (API/docs), but that is not the same thing as “there is a first-class enforcement predicate `matchFullCmdline`” in the v1.6.1 selector model.

So: **do not equate** `matchArgs` with owLSM’s **single-string** `process.cmd` field for prevention matching. The distinction is exactly what you were pushing on.

### 4) “I don’t see ‘Override on uprobes is only supported on x86_64’ — did you hallucinate? Is uprobe override impossible?”

**Not a hallucination — it is explicit in v1.6.1 upstream docs.**

From v1.6.1 `selectors.md`, under “#### Override action for uprobe”, immediately after the “here be dragons” warning, the text includes:

> Note that `Override` action can be used only on `x86_64` architecture.

So the product documentation for v1.6.1 claims an **Override** path exists for uprobes, but **arch-limited** and surrounded by extra constraints (also listed there: attach at function entry, `call` instruction, return type `int`, etc.).

How to reconcile that with your intuition “it’s not possible”:

- In **general eBPF engineering**, people often treat uprobe return tampering as **unsafe / limited / non-portable**.
- In **Tetragon’s documented surface**, v1.6.1 nonetheless describes a **vendor-supported** attempt — with strong warnings and narrow prerequisites.

For marketing copy aimed at shell-command prevention: it is still fair to say **bash `readline` uprobe enforcement is not a robust, portable replacement for LSM-class blocking**, without contradicting Tetragon’s own “exists but dangerous / constrained” documentation.

### 5) Stateful hook correlation — “same policy can list multiple hooks, but no correlation; impossible in Tetragon” — am I wrong?

**You are right about the product-level UX you care about (no user-authored cross-hook state machine like owLSM’s composed semantic events), but “impossible” is too strong as physics.**

What Tetragon gives you in one `TracingPolicy`:

- Multiple hook entries (`kprobes`, `tracepoints`, `uprobes`, `lsmhooks`, …) can coexist.
- There is **shared process/exec state** maintained by the agent/BPF layer (again: exec map / process metadata is real cross-hook infrastructure), and some features model cross-event linkage (FD follow/unfollow style actions appear in the same selectors doc family).

What it does **not** give you (compared to your owLSM pitch):

- A **single rule language field namespace** where a policy author writes one “logical event” and the platform automatically stitches unrelated hook points into that object for arbitrary fields (your “stateful enforcement_rules experience”).

So: **your differentiation is fair**, but phrase it as **“not offered as a first-class correlated enforcement schema”**, not “BPF cannot share maps across programs” (under the hood, obviously it can — Tetragon just does not expose owLSM’s model).

---

## Short recap table

| Your note | Verdict |
|-----------|---------|
| No general “contains” substring | Mostly yes (prefix/postfix exist) |
| No regex in kernel selectors | Yes (v1.6.1 operator list) |
| No `matchParentBinaries` in v1.6.1 CRD | Yes — but do not infer “only `task.real_parent`” |
| `resolve` == `fieldref` | No — different mechanism |
| Selector list OR, AND inside selector | Matches v1.6.1 docs (+ first-match action rule) |
| `matchArgs` ≠ full merged CMD for prevention | Correct emphasis |
| “Hallucinated x86_64 uprobe override line” | False alarm — present in v1.6.1 `selectors.md` |
| No owLSM-style cross-hook correlated rule object | Fair positioning; avoid “impossible” |
