# From YAML to Kernel Enforcement: Building a Sigma Rules Engine Inside eBPF

How we compiled human-readable Sigma rules into a stack-based expression evaluator running inside the Linux kernel.

---

## Introduction

Sigma rules look deceptively simple. A YAML file with some field names, a few string matches, and a condition like `selection and not filter`. Easy to read. Easy to write.

But try evaluating that logic inside an eBPF LSM hook — where you need to make a block/allow decision *before* a syscall completes — and things get complicated fast.

Consider what a real Sigma condition can look like:

```
(selection_passwd_write and not filter_root) or (selection_shadow_access and selection_non_root)
```

That's nested boolean logic with ANDs, ORs, NOTs, and parentheses. Each `selection_*` expands into multiple field comparisons — string contains, starts-with, numeric comparisons. The full expression tree can have dozens of nodes.

Now try running that inside the eBPF verifier's constraints: no recursion, no unbounded loops, 512-byte stack limit, and every memory access must be bounds-checked at compile time. Traditional expression evaluation techniques don't work here.

This post describes how we solved it: compiling Sigma Rules into a kernel-evaluable format that runs in under a microsecond per syscall.

---

## The Problem: A Concrete Example

Let's trace a specific rule through the entire pipeline. This rule blocks unauthorized write attempts to `/etc/passwd`:

```yaml
# More sigma metadata ...

description: "Block unauthorized /etc/passwd modifications"
action: "BLOCK_EVENT"
events:
    - WRITE
detection:
    selection_passwd:
        target.file.path:
            - "/etc/passwd"
            - "/etc/passwd-"
        target.file.path|contains: "passwd"
    selection_suspicious:
        process.file.path|endswith:
            - "python"
            - "perl"
            - "bash"
        process.effective_uid|above: 0
    filter_package_manager:
        process.file.path|startswith:
            - "/usr/bin/apt"
            - "/usr/bin/dpkg"
            - "/usr/bin/yum"
    condition: (selection_passwd and selection_suspicious) and not filter_package_manager
```

What does this rule actually express?

- **selection_passwd**: The target file is `/etc/passwd`, `/etc/passwd-`, or contains "passwd" in its path
- **selection_suspicious**: The process is a script interpreter (python/perl/bash) AND is running as non-root (UID > 0)
- **filter_package_manager**: Unless it's a package manager (apt/dpkg/yum)
- **condition**: Match if (passwd file AND suspicious process) AND NOT package manager

The condition combines:
- 3 string exact matches
- 1 substring search (`contains`)
- 3 suffix matches (`endswith`)
- 3 prefix matches (`startswith`)
- 1 numeric comparison (`above`)
- Nested ANDs, ORs, and a NOT

This needs to evaluate inside a kernel hook. Here's how we made it work.

---

## Stage 1: Parsing — YAML to AST

### AST Construction via pySigma

The detection logic is parsed into an Abstract Syntax Tree (AST) using [pySigma](https://github.com/SigmaHQ/pySigma), the official Sigma rule processing library. We implemented a custom pySigma Backend that, instead of generating SIEM query strings, extracts the boolean structure and builds lookup tables.

Here's how the rule above transforms into an AST:

**Input (condition):**
```
(selection_passwd and selection_suspicious) and not filter_package_manager
```

**Output (AST):**

```
                              AND
                            /     \
                         AND       NOT
                        /   \        \
              selection_passwd  selection_suspicious  filter_package_manager
```

But `selection_passwd`, `selection_suspicious`, and `filter_package_manager` are themselves compound expressions. Expanding them:

```
                                        AND
                                      /     \
                                   AND       NOT
                                  /   \        \
                                OR    AND      OR
                              / | \   / \    / | \
                            P0 P1 P2 AND P6  P7 P8 P9
                                    / | \
                                  P3 P4 P5
```

Where each `P` is an atomic **predicate** — a single field comparison:

| Predicate | Field | Comparison | Value |
|-----------|-------|------------|-------|
| P0 | `target.file.path` | EXACT | "/etc/passwd" |
| P1 | `target.file.path` | EXACT | "/etc/passwd-" |
| P2 | `target.file.path` | CONTAINS | "passwd" |
| P3 | `process.file.path` | ENDS_WITH | "python" |
| P4 | `process.file.path` | ENDS_WITH | "perl" |
| P5 | `process.file.path` | ENDS_WITH | "bash" |
| P6 | `process.effective_uid` | ABOVE | 0 |
| P7 | `process.file.path` | STARTS_WITH | "/usr/bin/apt" |
| P8 | `process.file.path` | STARTS_WITH | "/usr/bin/dpkg" |
| P9 | `process.file.path` | STARTS_WITH | "/usr/bin/yum" |

Notice how Sigma's YAML structure maps to boolean logic:
- Multiple values for one field → OR (e.g., the three paths under `selection_passwd`)
- Multiple fields within a selection → AND (e.g., `target.file.path` AND `process.file.path` in `selection_suspicious`)
- `not` keyword → NOT node

### Predicate Deduplication

Before moving forward, all predicates are **deduplicated** into a global table. If 10 different rules all check `target.file.path contains "passwd"`, that predicate is stored once and referenced by index everywhere. This deduplication is critical — it reduces kernel memory and enables the predicate result caching described later.

---

## Stage 2: Transformation — AST to Postfix (Reverse Polish Notation)

Here's where things get interesting. We need to evaluate that AST inside eBPF, but:

- **No recursion** — the verifier forbids it
- **No call stack** — we can't traverse a tree with function calls
- **512-byte stack limit** — we can't store arbitrary nested structures
- **No dynamic allocation** — no malloc, no variable-length anything

The solution: **convert the tree to postfix notation** (Reverse Polish Notation). Postfix expressions can be evaluated with a single linear pass using a fixed-size stack — no recursion, no operator precedence logic, no parentheses.

### The Conversion Algorithm

The algorithm walks the AST depth-first:
- **Predicate leaf**: emit a `PRED(idx)` token
- **AND/OR node**: emit all children recursively, then emit `N-1` operator tokens
- **NOT node**: emit the child, then emit a `NOT` token

Our example rule produces this token sequence:

```
P0 P1 OR P2 OR   P3 P4 OR P5 OR P6 AND   AND   P7 P8 OR P9 OR NOT   AND
└─────────────┘ └───────────────────────┘     └───────────────────┘
 selection_passwd   selection_suspicious         filter_package_manager
```

In words: "Evaluate P0 and P1, OR them, OR with P2 (that's selection_passwd). Evaluate P3, P4, P5, OR them all, AND with P6 (that's selection_suspicious). AND those two results. Evaluate P7, P8, P9, OR them all, NOT the result. AND with everything else."

### Why Postfix Works for eBPF

Postfix evaluation is beautifully simple:

1. Read tokens left to right
2. If it's a predicate → push onto the stack
3. If it's AND/OR → pop two values, compute result, push back
4. If it's NOT → pop one value, negate, push back
5. When done, the stack has exactly one value: the final result

This translates directly into a bounded loop with fixed stack size — exactly what the eBPF verifier wants.

---

## Stage 3: Pre-computation — String Matching Preparation

Before anything reaches the kernel, userspace pre-computes everything it can.

### The KMP DFA for Substring Search

The `CONTAINS` comparison needs substring search. The naive O(n×m) approach is too slow for inline syscall evaluation. KMP (Knuth-Morris-Pratt) gives us O(n), but standard KMP uses a failure function with conditional branches — problematic in eBPF where we want predictable execution.

We build a **complete DFA transition table** — a 2D array where `dfa[state][character]` gives the next state directly. No conditionals, no failure-function chasing.

For the pattern "passwd", the DFA looks like:

```
State 0: 'p' → 1, all others → 0
State 1: 'a' → 2, 'p' → 1, all others → 0  
State 2: 's' → 3, 'p' → 1, all others → 0
State 3: 's' → 4, 'p' → 1, all others → 0
State 4: 'w' → 5, 'p' → 1, all others → 0
State 5: 'd' → 6 (MATCH!), 'p' → 1, all others → 0
```

Each state has 256 entries (one per possible byte value). The kernel inner loop becomes:

```c
for (int i = 0; i < haystack_length; i++) {
    state = dfa[state * 256 + haystack[i]];
    if (state == match_state)
        return TRUE;
}
```

One array lookup per character. Zero branches inside the loop. Guaranteed O(n). The verifier sees a bounded loop with a static iteration count — perfect.

The trade-off is memory: `(pattern_length + 1) × 256` bytes per pattern. For "passwd" (6 chars), that's 1,792 bytes. Worth it for inline syscall evaluation.

---

## Stage 4: Kernel Evaluation — The Stack Machine

When a WRITE syscall fires, the eBPF hook runs.

### Event Population

First, the hook populates an event struct with all relevant context:
- `target.file.path` = "/etc/passwd"
- `process.file.path` = "/usr/bin/python3"
- `process.effective_uid` = 1000

### Postfix Evaluation with Short-Circuiting

The kernel walks the token array using a stack-based interpreter:

```
Token stream: P0 P1 OR P2 OR P3 P4 OR P5 OR P6 AND AND P7 P8 OR P9 OR NOT AND

Processing:
  P0: target.file.path EXACT "/etc/passwd" → TRUE, push
  P1: target.file.path EXACT "/etc/passwd-" → FALSE, push  
  OR: pop TRUE, FALSE → TRUE, push
  P2: target.file.path CONTAINS "passwd" → (short-circuit: already TRUE) skip, push TRUE
  
  P3: process.file.path ENDS_WITH "python" → FALSE (it's "python3"), push
  P4: process.file.path ENDS_WITH "perl" → FALSE, push
  OR: pop FALSE, FALSE → FALSE, push
  P5: process.file.path ENDS_WITH "bash" → FALSE, push
  OR: pop FALSE, FALSE → FALSE, push
  P6: process.effective_uid ABOVE 0 → TRUE (1000 > 0), push
  AND: pop FALSE, TRUE → FALSE, push  ← selection_suspicious failed!
  
  AND: pop TRUE (selection_passwd), FALSE (selection_suspicious) → FALSE, push
  
  (remaining tokens for filter_package_manager don't matter — outer AND will be FALSE)
  ...
  
  Final stack: [FALSE]
```

Wait — the rule **didn't match**. The process path is `/usr/bin/python3`, but we're checking for `ENDS_WITH "python"`. That doesn't match "python3".

This is actually correct behavior — it shows why the rule would need to be written with `|endswith: "python3"` or `|contains: "python"` to catch this case. The evaluation logic is working exactly as specified.

### Predicate Result Caching

The same predicate often appears in multiple rules. For example, many rules might check `target.file.path contains "passwd"`. Without caching, we'd run the KMP DFA search once per rule — dozens of times for the same event.

We maintain a predicate cache keyed by predicate index. When a predicate is evaluated, the result is stored. Subsequent rules checking the same predicate get an instant cache hit.

```c
cached = get_cached_result(predicate_idx, event_timestamp);
if (cached != UNKNOWN)
    return cached;

result = evaluate_predicate(predicate_idx, event);
cache_result(predicate_idx, result, event_timestamp);
return result;
```

The timestamp ensures the cache is implicitly invalidated between events.

### First Match Wins

Rules are stored sorted by ID. When a rule matches, evaluation stops immediately. Rule 1 takes precedence over rule 100. This differs from SIEM systems that evaluate all rules — but for inline enforcement, early exit is critical for performance.

---

## The Design Trade-offs

| Choice | Benefit | Cost |
|--------|---------|------|
| Postfix notation | No recursion, O(n) eval, verifier-friendly | Harder to debug than tree evaluation |
| Full KMP DFA | Single lookup per char, zero branches | Memory: (len+1) × 256 bytes per pattern |
| Predicate deduplication | Shared across rules, enables caching | Extra indirection |
| Predicate caching | Avoid redundant evaluation | Hash lookup overhead |
| First-match-wins | Early exit, O(1) best case | Rule ordering matters |

---

## Conclusion

Converting Sigma rules into kernel-evaluable logic required rethinking expression evaluation from first principles. The solution:

1. Parse YAML into an AST via pySigma
2. Convert the AST to postfix (RPN) for stack-based evaluation
3. Pre-compute KMP DFAs for O(n) substring matching with zero branches
4. Deduplicate and cache predicate evaluations across rules

The result: complex boolean expressions with string matching, numeric comparisons, and nested logic — evaluated inline inside eBPF hooks on the critical path of every syscall.
