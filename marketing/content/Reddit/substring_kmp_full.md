# How we implemented verifier-friendly O(n) substring search in eBPF LSM

We needed substring matching in our enforcement policy. I checked how other projects like Tetragon and KubeArmor handle it - turns out no open source project had done it.

So we built it ourselves. After trying multiple approaches, we found what works best. Our constraints:
- Haystack: 254 chars
- Needle: 32 chars
- Kernel 5.12+ support

I tweeted about it and got great feedback, so here's the full technical deep dive.

**The problem:** We needed `string_contains` for our rules, but it had to be efficient and verifier-friendly.

Naive substring search is O(n×m) with nested loops. Even with bounded loops, verifier complexity explodes.

**First attempt: Rabin-Karp**

We implemented Rabin-Karp. It mostly worked, but had two issues:
- Worst-case complexity of O(n×m)
- ~10% of kernels we tested had verifier issues

Pseudocode:
```c
struct string_utils_ctx 
{
    unsigned char haystack_length;
    char haystack[PATH_MAX];
    unsigned char needle_length;
    char needle[RULE_PATH_MAX];
};

static const unsigned long long RANDOM_BIG_NUMBERS[256] = {
    0x5956acd215fd851dULL, 0xe2ff8e67aa6f9e9fULL,
    0xa956ace215fd851cULL, 0x45ff8e55aa6f9eeeULL,
    // 255 random ull numbers
};

#define ROL64(v, r) (((unsigned long long)(v) << (r)) | ((unsigned long long)(v) >> (64 - (r))))

static inline unsigned long long window_hash_init(const char *window, unsigned char window_length)
{
    unsigned long long hash = 0;
    for (int i = 0; i < RULE_PATH_MAX; i++) 
    {
        if (i == window_length)
            break;
        hash ^= ROL64(RANDOM_BIG_NUMBERS[(unsigned char)window[i]], window_length - 1 - i);
    }
    return hash;
}

static inline int rabin_karp(const struct string_utils_ctx *sctx)
{
    unsigned char last = sctx->haystack_length - sctx->needle_length;
    unsigned long long haystack_hash = window_hash_init(sctx->haystack, sctx->needle_length);
    unsigned long long needle_hash = window_hash_init(sctx->needle, sctx->needle_length);

    for (int i = 0; i < PATH_MAX - RULE_PATH_MAX + 1; i++) 
    {
        if (i > last)
            break;

        if (haystack_hash == needle_hash) 
            return i; 

        if (i < last) 
        {
            unsigned long long out = ROL64(RANDOM_BIG_NUMBERS[(unsigned char)sctx->haystack[i]], sctx->needle_length);
            haystack_hash = ROL64(haystack_hash, 1)              
                ^ out                                                                      // remove
                ^ RANDOM_BIG_NUMBERS[(unsigned char)sctx->haystack[i + sctx->needle_length]]; // insert
        }
    }
    
    return -1;
}
```

**Final solution: Precomputed KMP → DFA**

In userspace:
1. Parse each pattern string
2. Build the KMP failure function
3. Convert to a full DFA (256 chars × pattern_length states)
4. Store flattened DFA in a BPF map

DFA construction (simplified):
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

Single bounded loop, one map lookup per char, O(n) time. Verifier happy.

**Trade-off:** ~64KB per pattern (256 states × 256 chars). Acceptable for our use case.

Has anyone else tackled substring matching in eBPF differently?
