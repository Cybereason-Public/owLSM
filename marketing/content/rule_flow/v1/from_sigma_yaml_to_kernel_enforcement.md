# From Sigma YAML to Kernel Enforcement: The Full Rule Pipeline

How owLSM compiles human-readable security rules into a stack-based expression evaluator running inside the Linux kernel via eBPF.

---

## Introduction

owLSM is a Linux security tool that monitors and controls system behavior in real-time using eBPF hooks. At its core lies a rule engine: security analysts write detection rules in a Sigma-like YAML format, and these rules are evaluated **inline** — directly inside kernel syscall hooks — to decide whether to allow, block, or kill a process *before* the operation completes.

This is fundamentally different from traditional SIEM systems that analyze logs post-hoc. owLSM must evaluate complex boolean expressions with string matching, numeric comparisons, and IP CIDR checks — all within the strict constraints of the eBPF verifier, with hard limits on loops, stack size, and memory access.

This post walks through the full pipeline: from a YAML rule file to a kernel-space decision in under a microsecond.

---

## The Three-Stage Pipeline

The rule lifecycle flows through three distinct stages:

```
  ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
  │   YAML Rules    │       │   JSON Config    │       │   BPF Maps      │
  │   (Sigma-like)  │ ───▶  │   (Serialized)  │ ───▶  │   (Kernel)      │
  └─────────────────┘       └─────────────────┘       └─────────────────┘
     Rules Generator            Userspace C++            eBPF Programs
       (Python)                                       
```

1. **Rules Generator** (Python) — Compiles YAML rules into a JSON intermediate representation
2. **Userspace Loader** (C++) — Deserializes JSON and populates BPF maps, including pre-computing KMP DFAs
3. **Kernel Evaluator** (eBPF) — Evaluates rules against live events using a stack-based postfix interpreter

---

## Stage 1: Rules Generator — YAML to JSON

### Starting Point: A Sigma-Like Rule

Let's trace a concrete rule through the entire pipeline. This rule detects unauthorized SSH key access:

```yaml
id: 100
description: "Detect unauthorized SSH private key access"
action: "BLOCK_EVENT"
events:
    - READ
detection:
    selection_ssh_keys:
        target.file.path|contains:
            - ".ssh/id_rsa"
            - ".ssh/id_ed25519"
    selection_suspicious_process:
        process.file.filename|endswith:
            - "curl"
            - "wget"
    filter_authorized:
        process.file.path|startswith:
            - "/usr/bin/ssh"
            - "/usr/bin/scp"
    condition: selection_ssh_keys and selection_suspicious_process and not filter_authorized
```

The Rules Generator processes this through five steps. See [Diagram 1: Rules Generator Pipeline](#diagrams) for a visual overview.

### Step 1: Schema Validation

Each YAML file is loaded and validated against the owLSM rule schema. The validator checks:
- Required fields (`id`, `description`, `action`, `events`, `detection`)
- Field-event compatibility (e.g., `target.file.path` is valid for `READ` but not `EXEC`)
- Modifier validity (e.g., `contains` only on string fields, `cidr` only on IP fields)
- Value types and ranges

This catches errors early, before any compilation occurs.

### Step 2: AST Construction via pySigma

The detection logic is parsed into an Abstract Syntax Tree (AST) using [pySigma](https://github.com/SigmaHQ/pySigma), the official Sigma rule processing library. owLSM implements a **custom pySigma Backend** (`OwlsmBackend`) that, instead of generating query strings for a SIEM, builds three lookup tables and an expression tree.

As pySigma walks the detection section, each comparison it encounters is converted into a **predicate** — a self-contained, atomic comparison unit. During this traversal, the backend builds three deduplicated lookup tables:

**`id_to_string`** — Every unique string value gets a numeric ID:

```
0: { value: ".ssh/id_rsa",    is_contains: true  }
1: { value: ".ssh/id_ed25519", is_contains: true  }
2: { value: "curl",            is_contains: false }
3: { value: "wget",            is_contains: false }
4: { value: "/usr/bin/ssh",    is_contains: false }
5: { value: "/usr/bin/scp",    is_contains: false }
```

The `is_contains` flag marks strings requiring substring search — these will need KMP DFA pre-computation later.

**`id_to_predicate`** — Each unique comparison becomes a predicate with three components:

| idx | field | comparison_type | string_idx |
|-----|-------|----------------|------------|
| 0 | `target.file.path` | CONTAINS | 0 |
| 1 | `target.file.path` | CONTAINS | 1 |
| 2 | `process.file.filename` | ENDS_WITH | 2 |
| 3 | `process.file.filename` | ENDS_WITH | 3 |
| 4 | `process.file.path` | STARTS_WITH | 4 |
| 5 | `process.file.path` | STARTS_WITH | 5 |

Predicates are **deduplicated** across rules. If five different rules all check `target.file.path contains ".ssh/id_rsa"`, that predicate is stored once and referenced by index everywhere. This deduplication is critical — it reduces kernel memory usage and enables the predicate result caching described later.

**`id_to_ip`** — IP addresses and CIDR ranges are stored in a separate table (not used in this example, but would contain entries like `{ ip: "10.0.0.0", cidr: 8, ip_type: AF_INET }`).

The condition expression itself is captured as a tree:

```
                      AND
                    /  |  \
                 AND   |   NOT
                / \    |     \
             OR    OR  |     OR
            / \   / \  |    / \
          P0  P1 P2 P3 |  P4  P5
```

Where `P0` through `P5` reference the predicate table entries. Note how Sigma's YAML structure maps to boolean logic: multiple values for one field become OR (the lists under `selection_ssh_keys`), while multiple fields within a selection become AND.

### Step 3: Infix-to-Postfix Conversion (Reverse Polish Notation)

The AST is converted to **postfix notation** (Reverse Polish Notation) via a recursive tree traversal. This is the key transformation that makes kernel evaluation possible.

Why postfix? In the eBPF kernel environment, we cannot use recursion (the verifier forbids it), and we have severe stack size limits. Postfix expressions can be evaluated with a single linear pass using a stack — no recursion, no operator precedence logic, no parentheses. It's the ideal representation for a constrained execution environment.

The conversion algorithm walks the AST depth-first. For each node:
- **Predicate leaf**: emit a `PRED(idx)` token
- **AND/OR node**: emit all children recursively, then emit `N-1` operator tokens (where N = number of children)
- **NOT node**: emit the child, then emit a `NOT` token

Our example rule produces this token sequence:

```
PRED(0) PRED(1) OR  PRED(2) PRED(3) OR  AND  PRED(4) PRED(5) OR  NOT  AND
```

Reading left to right: "push P0, push P1, OR them; push P2, push P3, OR them; AND the two results; push P4, push P5, OR them; NOT that; AND everything."

### Step 4: Serialization to JSON

The tables and postfix token arrays are serialized into a JSON structure:

```json
{
    "id_to_string": {
        "0": { "value": ".ssh/id_rsa", "is_contains": true },
        "1": { "value": ".ssh/id_ed25519", "is_contains": true },
        ...
    },
    "id_to_predicate": {
        "0": { "field": "target.file.path", "comparison_type": "CONTAINS", "string_idx": 0 },
        ...
    },
    "id_to_ip": {},
    "rules": [
        {
            "id": 100,
            "description": "Detect unauthorized SSH private key access",
            "action": "BLOCK_EVENT",
            "applied_events": ["READ"],
            "tokens": [
                { "operator_type": 0, "predicate_idx": 0 },
                { "operator_type": 0, "predicate_idx": 1 },
                { "operator_type": 2 },
                ...
            ]
        }
    ]
}
```

This JSON is embedded into the `config.json` passed to owLSM at startup.

---

## Stage 2: Userspace — JSON to BPF Maps

The C++ userspace component loads the JSON config and transforms it into kernel-ready data structures inside BPF maps.

### Deserialization and Schema Validation

The JSON is first validated against a schema (using the Valijson library), then deserialized using nlohmann/json into C++ structs (`RuleString`, `Predicate`, `RuleIP`, `Rule`). For IP addresses, strings like `"10.0.0.0"` are converted to their binary network-byte-order representation — the kernel will compare raw integers, not strings.

### KMP DFA Pre-Computation

This is where one of the most technically interesting transformations happens. For every string marked with `is_contains: true`, userspace pre-computes a **Knuth-Morris-Pratt Deterministic Finite Automaton**.

The classic KMP algorithm achieves O(n) substring matching by pre-computing a failure function that avoids re-scanning characters after a mismatch. owLSM takes this further: instead of storing just the failure function, it builds a **complete DFA transition table** — a 2D array of `(state × 256)` entries, where each entry gives the next state for any input character.

```cpp
// Flat 2D DFA: dfa[state * 256 + character] = next_state
for (size_t state = 0; state <= pattern_len; ++state)
{
    for (int c = 0; c < 256; ++c)
    {
        size_t idx = (state * DFA_ALPHABET_SIZE) + c;
        if (state < pattern_len && pattern[state] == c)
            dfa.value[idx] = state + 1;      // match: advance
        else if (state == 0)
            dfa.value[idx] = 0;               // no prefix: restart
        else
            dfa.value[idx] = dfa.value[failure[state-1] * 256 + c]; // follow failure
    }
}
```

Why a full DFA instead of the standard KMP failure array? In eBPF, we need **predictable, branchless iteration**. The DFA reduces the kernel inner loop to a single array lookup per character — no conditional failure-function chasing, no variable-length backtracking. The trade-off is memory: each DFA consumes `(pattern_length + 1) × 256` bytes. But the guarantee of O(n) worst-case with zero branches per character is worth it for inline syscall evaluation.

### BPF Map Population

Userspace populates six categories of BPF maps:

| Map | Type | Purpose |
|-----|------|---------|
| `predicates_map` | Array | Global predicate table |
| `rules_strings_map` | Array | String values with length and DFA index |
| `idx_to_DFA_map` | Array | Pre-computed KMP DFAs for `contains` strings |
| `rules_ips_map` | Array | IP addresses in binary form with CIDR masks |
| `{event}_rules` | Array | Per-event-type rule arrays (e.g., `read_rules`, `exec_rules`) |
| `predicates_results_cache` | Hash | Predicate result cache (per-event) |

The **per-event-type rule maps** are a critical optimization. A rule with `events: [READ]` is only inserted into `read_rules`. When a READ syscall fires, the kernel iterates *only* over `read_rules` — never touching EXEC, WRITE, or NETWORK rules. A rule applying to multiple events (e.g., `events: [CHMOD, CHOWN, READ, WRITE]`) is inserted into all relevant maps.

After population, maps are **frozen** — they become read-only in kernel space, which enables the verifier to make stronger assumptions and produces more efficient JIT code.

---

## Stage 3: Kernel Evaluation — BPF Maps to Decision

When a syscall fires, the eBPF hook must decide: allow, block, or kill. See [Diagram 2: Kernel Evaluation Flow](#diagrams) for a visual overview.

### Event Population

First, the hook populates an `event_t` struct with all relevant context: process info (PID, UID, command line, executable path), parent process info, and event-specific data (target file path for READ, network addresses for CONNECT, etc.). This struct becomes the "row" that rules are evaluated against.

### Rule Iteration

The kernel calls `bpf_for_each_map_elem` on the event-specific rule map (e.g., `read_rules` for a READ event). This BPF helper iterates over every entry in the map, calling a callback function for each rule.

Rules are stored **sorted by ID** (lowest first). This is important because owLSM uses a **first-match-wins** strategy: evaluation stops at the first matching rule. Rule 1 takes precedence over rule 100. This differs from traditional SIEM systems that process all rules and aggregate results — but it's far more efficient for inline enforcement where microseconds matter.

### Stack-Based Postfix Evaluation

For each rule, the kernel evaluates the postfix token array using a stack-based interpreter. The algorithm processes tokens left to right:

1. **PREDICATE token**: Push it onto the stack (evaluation is deferred).
2. **AND operator**: Pop two operands. Evaluate the first — if FALSE, short-circuit (push FALSE without evaluating the second). Otherwise evaluate the second and push the result.
3. **OR operator**: Pop two operands. Evaluate the first — if TRUE, short-circuit (push TRUE). Otherwise evaluate the second.
4. **NOT operator**: Pop one operand, evaluate it, push the negation.

After processing all tokens, the stack should contain exactly one element — the final boolean result.

The **short-circuit evaluation** (AND skips the second operand if the first is false; OR skips if the first is true) is a significant performance optimization. In our SSH key example, if `selection_ssh_keys` doesn't match (the file path doesn't contain `.ssh/id_rsa` or `.ssh/id_ed25519`), the entire rule fails immediately without ever checking the process name or the filter.

### Predicate Evaluation

When a PREDICATE token is actually evaluated (not short-circuited), the kernel looks up the predicate from `predicates_map` and dispatches based on comparison type:

**String comparisons:**
- `EXACT_MATCH` — byte-by-byte comparison with length check
- `STARTS_WITH` — compare the first N bytes
- `ENDS_WITH` — compare the last N bytes
- `CONTAINS` — run the pre-computed KMP DFA

**Numeric comparisons:**
- `EQUAL`, `ABOVE` (>), `BELOW` (<), `EQUAL_ABOVE` (>=), `EQUAL_BELOW` (<=)
- Handles PIDs, UIDs, port numbers, permission modes, etc.

**IP comparisons:**
- CIDR matching via bitwise AND with the pre-computed subnet mask
- Supports both IPv4 (32-bit) and IPv6 (128-bit, compared as four 32-bit words)

### The KMP DFA in Action

When the kernel encounters a `CONTAINS` comparison, it runs the pre-computed DFA:

```c
unsigned int state = 0;
unsigned int match_state = needle_length;
for (int i = 0; i < haystack_length && i < PATH_MAX; i++)
{
    unsigned int c = (unsigned char)haystack[i];
    state = dfa->value[(state * 256) + c];  // single lookup per character
    if (state == match_state)
        return TRUE;
}
return FALSE;
```

One array lookup per character, zero backtracking, guaranteed O(n) — exactly what we need inside a syscall hook. The verifier is happy because the loop bound is static (`PATH_MAX`), and there are no unpredictable branches.

### Predicate Result Caching

The same predicate often appears in multiple rules. For example, many rules might check `target.file.path contains ".ssh"`. Without caching, this KMP DFA search would run once per rule — potentially dozens of times for the same event.

owLSM maintains a `predicates_results_cache` BPF hash map. The cache uses the event timestamp as a generation counter: when a predicate is evaluated, the result (TRUE/FALSE) is stored along with the current event's timestamp. On subsequent lookups, if the stored timestamp matches the current event, the cached result is returned immediately.

```c
// Check cache first
enum token_result cached = get_cached_pred_result(pred_idx, event);
if (cached != TOKEN_RESULT_UNKNOWN)
    return cached;  // cache hit — skip evaluation

// Cache miss — evaluate and store
int result = eval_pred(pred_idx, event);
set_cached_pred_result(pred_idx, result, event);
return result;
```

This is effectively a **memoization table** over predicate evaluations, scoped to the current event. The timestamp-based invalidation ensures no stale results carry over between events — the cache is implicitly cleared when the next event arrives.

### First Match Wins

When a rule matches, the callback sets the action on the event struct and returns `1` to stop iteration:

```c
if (evaluate_rule_against_event(current_rule, current_event) == TRUE)
{
    current_event->action = current_rule->action;
    current_event->matched_rule_id = current_rule->id;
    return 1;  // stop iterating
}
return 0;  // continue to next rule
```

After iteration completes, the action is enforced:
- `ALLOW_EVENT` — the syscall proceeds, event is sent to userspace
- `BLOCK_EVENT` — the syscall is denied (returns `-EPERM`)
- `BLOCK_KILL_PROCESS` — syscall denied and the process is terminated
- `EXCLUDE_EVENT` — the syscall proceeds, no event is sent (noise reduction)

---

## Full Example Trace

Let's trace our SSH key rule when `curl` tries to read `/home/user/.ssh/id_rsa`:

1. **READ hook fires**. The kernel populates `event_t` with:
   - `target.file.path = "/home/user/.ssh/id_rsa"`
   - `process.file.filename = "curl"`
   - `process.file.path = "/usr/bin/curl"`

2. **Iterate `read_rules`**. Rule 100 is reached.

3. **Evaluate postfix tokens**:
   - `PRED(0)`: Is `target.file.path` CONTAINS `".ssh/id_rsa"`? → Run KMP DFA → **TRUE**. Cache it.
   - `PRED(1)`: Is `target.file.path` CONTAINS `".ssh/id_ed25519"`? → Run KMP DFA → **FALSE**. Cache it.
   - `OR`: TRUE OR FALSE → **TRUE**
   - `PRED(2)`: Is `process.file.filename` ENDS_WITH `"curl"`? → Compare last 4 bytes → **TRUE**. Cache it.
   - `PRED(3)`: (short-circuited by prior OR? No — this is under a different OR)
     Is `process.file.filename` ENDS_WITH `"wget"`? → **FALSE**. Cache it.
   - `OR`: TRUE OR FALSE → **TRUE**
   - `AND`: TRUE AND TRUE → **TRUE**
   - `PRED(4)`: Is `process.file.path` STARTS_WITH `"/usr/bin/ssh"`? → Compare first 12 bytes: `"/usr/bin/curl"` vs `"/usr/bin/ssh"` → **FALSE**. Cache it.
   - `PRED(5)`: Is `process.file.path` STARTS_WITH `"/usr/bin/scp"`? → **FALSE**. Cache it.
   - `OR`: FALSE OR FALSE → **FALSE**
   - `NOT`: NOT FALSE → **TRUE** (filter doesn't match, so we don't exclude)
   - `AND`: TRUE AND TRUE → **TRUE**

4. **Rule matches** → action = `BLOCK_EVENT`. The READ syscall returns `-EPERM`. curl gets "Permission denied". The SSH key is safe.

---

## Design Trade-offs

| Design Choice | Benefit | Cost |
|---------------|---------|------|
| Postfix (RPN) notation | No recursion, O(n) evaluation, verifier-friendly | Harder to debug than tree-based evaluation |
| Full KMP DFA (not just failure function) | Single lookup per character, zero branches | Memory: (pattern_len+1) × 256 bytes per pattern |
| Predicate deduplication | Shared across rules, enables caching | Extra indirection layer |
| Per-event-type rule maps | Only relevant rules checked per syscall | Rule duplication across maps |
| Predicate result caching | Avoid redundant evaluations across rules | Hash map lookup overhead per predicate |
| First-match-wins | Early exit, O(1) best case | Rule ordering matters — requires careful rule ID assignment |

---

## Diagrams

### Diagram 1: End-to-End Pipeline

See `end_to_end_pipeline.drawio` — high-level view of all three stages from YAML to kernel decision.

### Diagram 2: Rules Generator Pipeline

See `rules_generator_pipeline.drawio` — illustrates the step-by-step transformation from YAML to JSON, including the lookup table construction.

### Diagram 3: Kernel Evaluation Flow

See `kernel_evaluation_flow.drawio` — illustrates the per-event rule iteration, postfix stack machine, predicate evaluation dispatch, and action enforcement.

---

## Conclusion

The owLSM rule pipeline bridges the gap between human-readable security policy and kernel-speed enforcement. Sigma-like YAML rules pass through an AST-based compiler using pySigma, are converted to Reverse Polish Notation for stack-based evaluation, benefit from KMP DFA pre-computation for O(n) substring matching, and leverage predicate deduplication with memoized caching — all to evaluate complex boolean expressions inside eBPF hooks on the critical path of every monitored syscall.

The result: security rules that are as easy to write as Sigma detections, but enforced inline at kernel speed with the power to block attacks before they complete.
