# How we implemented substring which is verifier-friendly and O(n) in EBPF LSM.

We tried to create a sigma rules engine using EBPF LSM. 
I want to explain to you 1 technical deep dive about a problem we had.

**The problem:** We needed `string_contains` for our rules, but it had to be efficient and verifier friendly. Support Kernel 5.12 and above.

Naive substring search is O(n*m) with nested loops. Even with bounded loops, the verifier complexity explodes. We needed O(n) single-pass.

**Our solution: Precomputed KMP→DFA**

Full architecture docs: https://cybereason-public.github.io/owLSM/architecture/rule-evaluation.html

In userspace, we:
1. Parse each pattern string
2. Build the KMP failure function
3. Convert failure function into a full DFA (256 chars × pattern_length states)
4. Store flattened DFA in a BPF map

The DFA build (simplified):
```c
for (state = 0; state <= pattern_len; state++) {
    for (c = 0; c < 256; c++) {
        if (pattern[state] == c)
            dfa[state * 256 + c] = state + 1;  // advance
        else
            dfa[state * 256 + c] = dfa[failure[state-1] * 256 + c];  // follow failure
    }
}
```

In eBPF, the search becomes trivial:
```c
for (i = 0; i < haystack_length && i < PATH_MAX; i++) {
    state = dfa->value[(state * 256) + haystack[i]];
    if (state == match_state) return TRUE;
}
```

Single bounded loop, single map lookup per char, O(n) time. Verifier happy.

**Trade-off:** ~64KB per pattern (256 states × 256 chars). We accept this for the patterns we need.

Curious if anyone else has tackled substring matching in eBPF differently.