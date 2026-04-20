# How we implemented verifier-friendly regex engine in eBPF LSM

We are implementing a Sigma rules engine, so we need to support regex matching.
I checked how other projects like Tetragon and KubeArmor do it. Turns out no open source project had done it. So we built it ourselves.
Thus, owLSM is the first open source project to implement a verifier-friendly regex engine in eBPF.


**The problem:** We needed regex matching for our rules, but it had to be efficient and verifier-friendly. Its runtime had to be O(n).
However, modern regex engines are too complex for eBPF and can reach O(2^n) due to backtracking.

# First approach — kfuncs

I read [Dawid Macek’s blog](https://www.dawidmacek.com/posts/2025/regex-in-ebpf/) on how he solved the issue.
He moved the regex logic into a kernel module that exposes an API eBPF programs call via kfuncs.
That way the heavy work bypasses the verifier because the real regex logic lives in the kernel module.

I treated that as a last resort.
I did not want to introduce a kernel module into owLSM, because it creates many new issues: crashes, Secure Boot, maintenance, etc.


# Second approach: regex → AST → NFA → DFA

Modern regex engines are too complex. With backtracking, evaluation can reach O(2^n). That is not acceptable for our use case or for the verifier.  
I looked for other implementations of regex engines and found that older engines like the one used in `grep` avoid backtracking, so they can be implemented in O(n).  
I dug into the subject and found Russ Cox’s write-up: https://swtch.com/~rsc/regexp/regexp1.html  

This fit well because the project already uses DFAs for substring matching, as I described in a different post: https://www.reddit.com/r/eBPF/comments/1rw7tru/how_we_implemented_verifierfriendly_on_substring/  
Runtime DFA evaluation is almost the same for substring matching and for regex. I only needed to convert the regex pattern to a DFA.  
So first I converted the regex pattern to an AST.  
Then the AST is converted to an NFA.  
Then the NFA is converted to a DFA.  
Then the DFA is flattened to a DFA table plus accepting states.  
See the regex-to-DFA code: https://github.com/Cybereason-Public/owLSM/blob/f05be7e0ce72391cf691648b8cd4e2b79bc31800/src/Userspace/rules_managment/dfa_builder.cpp#L1085  
That compilation runs in userspace.  


At runtime we evaluate the regex in O(n) like this:

```c
for (i = 0; i < haystack_length && i < PATH_MAX; i++) {
    state = dfa->value[(state * 256) + haystack[i]];
    if (is_accepting(state)) return TRUE;
}
```

Single bounded loop, one map lookup per character, O(n) time. The verifier stays happy.

# Regex features we support

| Feature | Syntax | Example |
|---------|--------|---------|
| Literals | normal characters | `"abc"` |
| Character ranges | `[a-z]`, `[0-9A-F]` | `"[a-z]+"` |
| Negated ranges | `[^a-z]`, `[^/]` | `"[^/]+"` |
| Character classes | `\d`, `\w`, `\s` | `"\\d+"` |
| Negated classes | `\D`, `\W`, `\S` | `"\\D+"` |
| Dot (printable ASCII) | `.` | `"a.c"` |
| Alternation | `a|b` | `"cat|dog"` |
| Grouping | `(...)` | `"(ab)+"` |
| Repetition | `*`, `+`, `?` | `"ab*c"`, `"a+"` |
| Bounded repetition | `{n}`, `{n,m}`, `{n,}` | `"a{2,4}"` |
| Non-greedy | `*?`, `+?`, `??` | `"a+?"` |
| Case insensitive | `(?i)` | `"(?i)hello"` |
| Escape sequences | `\n`, `\t`, `\\`, `\.` | `"a\\.b"` |

**Regex state limit:** Regex patterns are compiled to deterministic finite automata (DFAs) for efficient O(n) matching in the kernel. Each DFA is limited to **32 states**. Complex patterns with many branches or long literals may exceed this limit—if so, simplify the pattern. In practice, you are unlikely to hit this limit.
