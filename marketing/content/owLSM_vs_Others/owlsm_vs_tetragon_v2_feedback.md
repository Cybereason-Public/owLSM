# Fact-check feedback: `owlsm_vs_tetragon_v2.md` vs Tetragon **v1.6.1**

Research sources: **Tetragon Docs MCP** (`search_tetragon_documentation`, `search_tetragon_code`) and **pinned release artifacts** on GitHub (`https://github.com/cilium/tetragon/tree/v1.6.1`).  
Note: GitMCP documentation search often surfaces `main`-branch docs; where `main` and **v1.6.1** differ, this feedback calls that out explicitly.

---

## Meta: scope and wording

- Treating Sigma (owLSM) vs TracingPolicy (Tetragon) both as “enforcement_rules” is a reasonable shorthand for the article, as long as you clarify that Tetragon’s object model is hook-centric (kprobe / tracepoint / uprobe / `lsmhooks`) plus in-kernel selectors and actions, while owLSM is event-schema-centric with compiled Sigma logic.
- Several statements are **directionally right** but need **precision** so a Tetragon maintainer does not dismiss the piece on the first nit.

---

## Important points (intro)

| Claim | Verdict | Notes |
|--------|---------|--------|
| Prevention vs monitoring definitions | OK | Matches how Tetragon documents “monitoring” vs “enforcement” policy modes (`policy-mode` option, enforcement docs). |
| “Tetragon is better for monitoring” | Opinion | Defensible competitively, but not something to “fact check” against code; keep as clearly labeled opinion. |
| “owLSM is better for prevention” | Opinion | Same as above. |

---

## owLSM has / Tetragon does not (enforcement_rules)

### Substring matching

- **Mostly supported, but over-broad as written.**  
  Tetragon v1.6.1 documents string operators on arguments such as `Equal`, `NotEqual`, **`Prefix` / `Postfix`** (and “Not” variants where applicable), plus numeric / network-style operators (`docs/content/en/docs/concepts/tracing-policy/selectors.md` on tag v1.6.1).  
- That is **not** the same as a general “substring / contains anywhere in the middle” operator for arbitrary fields. If you mean “infix contains”, say Tetragon lacks that (unless you approximate with multiple hooks or post-processing).

### Regex matching

- **Supported as stated for in-kernel `matchArgs` / `matchData` string matching** in the documented operator lists: there is **no** regex operator alongside the documented set (same `selectors.md` v1.6.1).

### Fieldref-style “compare two fields of the same event”

- **Mostly supported as a different mechanism.**  
  Tetragon can correlate data from kernel objects via `resolve` on kprobe/LSM arguments (documented with kernel-version caveats: kprobe ≥5.4, LSM ≥5.7; **not** for uprobes in the same doc section). That is “walk a struct field”, not Sigma’s `fieldref` syntax, but it overlaps the *intent* (derive one field from another at evaluation time).  
- Worth a sentence so readers do not think Tetragon can only match literals.

### Conditions (`and` / `or` / `not` / parentheses)

- **Partially overstated.**  
  In v1.6.1 `selectors.md`: **all filters inside one selector are ANDed**; **multiple selectors on the same hook are disjunctive (OR)** with “first matching selector wins” for actions, and hooks are capped (doc: **up to 5 selectors per hook** on v1.6.1).  
- You can get **NOT**-style logic via operators like `NotEqual`, `NotPrefix`, etc., and reuse fragments via `selectorsMacros`, but this is **not** an arbitrary boolean expression language like rich Sigma condition trees.

### “Standard rules language” / SigmaHQ import

- **Marketing OK, engineering nuance required.**  
  Sigma is widely used, but **Linux Sigma rules are not automatically portable** to any engine: fields, categories, logsource expectations, and backends differ. For owLSM, “import from SigmaHQ” is usually **adapt**, not literal plug-and-play—worth one honest clause so credibility holds.

### “Tetragon needs deep kernel knowledge”

- **Partly true, partly softened by Tetragon itself.**  
  TracingPolicy is absolutely hook- and argument-type-driven (you must know what you are attaching to). At the same time, Tetragon documents **portable syscall symbol names** (e.g. `sys_write` without architecture prefixes) and `resolve` helpers so users are not always hand-walking raw offsets. Keep the claim, but allow that Tetragon mitigates *some* portability pain.

### Full process command line as a single matchable string

- **Needs splitting “events” vs “selector language”.**  
  - **Events / API:** Tetragon’s `Process` message includes an `arguments` string (see `docs/content/en/docs/reference/grpc-api.md`); examples in policy-library docs use `jq` with `contains()` on exported JSON—**monitoring / post-processing** clearly can see a full argv-style string.  
  - **In-kernel enforcement selectors:** matching is expressed through **`matchArgs` on the probed function’s arguments**, **`matchBinaries`** on the executable path (with optional `followChildren`), etc.—not through a single first-class “full argv string” selector parallel to owLSM’s merged `/proc/.../cmdline`-style field.  
- So: your **comparison to owLSM’s enforcement-time “one string cmdline” abstraction** is reasonable; the absolute wording “Tetragon doesn’t offer you the full process CMD” is easy to attack **if** a reader thinks you mean “nowhere in Tetragon” rather than “not as a dedicated enforcement match field”.

### “Original parent” / reparenting to PID 1 vs owLSM state

- **This section is the biggest version hazard for v1.6.1.**  
  - Tetragon is **not** “stateless” in the sense of having no process cache: BPF side maintains an `execve_map` with a **`pkey` (parent key)** and binary metadata (`bpf/lib/process.h` on v1.6.1). Parent/child relationships in exported events also use stable identifiers like `exec_id` / `parent_exec_id` in the API.  
  - Separately, the **public CRD for v1.6.1** (`pkg/k8s/apis/cilium.io/v1alpha1/types.go` on tag v1.6.1) shows `KProbeSelector` includes `matchPIDs`, `matchArgs`, `matchData`, `matchBinaries`, etc., but **does not include `matchParentBinaries`**, which *does* appear in newer `main`-branch reference tables the MCP sometimes returns. **Do not attribute `matchParentBinaries` to v1.6.1** unless you re-verify your installed CRD.  
- Net: reparenting can still produce confusing **parent** views in edge cases (docs discuss flags like `taskWalk` / `miss` around parent reconstruction), but the blanket “always live parent, therefore PID 1” story is **too strong** without qualifiers and without pinning to the exact filter you mean (`matchBinaries` vs event `parent` vs hypothetical parent-binary selectors).

### Kill / signal parent vs child helper binaries

- **Directionally right on first-class actions.**  
  Documented actions like `Sigkill` / `Signal` are framed around the **process making the call** (see `selectors.md` v1.6.1). There is no documented, symmetric “kill spawning parent session” knob comparable to your owLSM story—**unless** you chain policies / hooks creatively (which is not the same as productized “kill parent”).  
- Tetragon also documents combining **`Signal` with `Override`** when you need to block an operation *and* stop the task—nuance your text can mention so it does not look unaware of enforcement caveats.

### Shell commands: uprobes “cannot block”; dash

- **“Cannot block via uprobes” is too absolute for v1.6.1.**  
  The same `selectors.md` (v1.6.1) documents an **`Override` action for uprobes**, including `argRegs` tricks—but with **strong warnings**, practical constraints (e.g. documented note that **Override on uprobes is only supported on x86_64** on v1.6.1), and assumptions about function prologue / return type.  
- Your **practical** point still stands: using `bash:readline` as a generic “shell command firewall” is brittle, does not cover `dash` without separate probes, and uprobe override is **not** a safe, portable replacement for LSM-style decisions. Rephrase from “cannot” to “not practically / not portably / not safely” and cite Tetragon’s own warnings.

### Stateful hook correlation (multi-hook story)

- **Reasonable differentiation.**  
  Tetragon can combine hooks in policies, but the **user** still wires the hooks; owLSM’s pitch is precomposed semantic events. Keep as positioning, not as a unique impossibility for Tetragon power-users.

### FlatBuffers vs protobuf / JSON

- **Uncontroversial at a high level** for v1.6.1-era Tetragon (JSON + protobuf paths are mainstream). “Orders of magnitude” reader-side efficiency is plausible but **benchmark-dependent**—optional weasel word unless you have numbers.

---

## Tetragon has / owLSM does not

### “Prevention on every hooking point the kernel exports (all LSM + all kprobes with bpf_override_return)”

- **Overstated; should be tightened.**  
  - **Kprobes / overrides:** Tetragon’s own override documentation ties generic kprobe override to kernel **error injection** / supported mechanisms (`CONFIG_BPF_KPROBE_OVERRIDE`, `ALLOW_ERROR_INJECTION()` / `security_` hooks on ≥5.7 in the documented note). That is **not** “every kprobe symbol you can attach to”.  
  - **LSM:** availability depends on **BPF LSM being enabled in the running LSM stack** (`lsm=` includes `bpf`), not only on `CONFIG_BPF_LSM=y` in config—Tetragon documents this in the hooks/LSM material.  
  - **Hook surface in a given release:** even where BPF can attach, **policy features** (for example IMA-related `Post` behavior) are documented against **explicit hook allowlists**, not “all of `security.c`” in the sense of one turnkey enforcement knob per hook.  
- Better sentence: **“Broad, user-chosen attachment surface (subject to kernel/BTF/feature gating)”** instead of “every exported hook”.

### Kubernetes vs “Linux machines”

- **Mostly fair, but add one line:** Tetragon’s v1.6.1 FAQ explicitly says it can run **standalone outside Kubernetes** (container/package install paths). Your comparison is still valid for **first-class workload identity & policy ergonomics** on Kubernetes.

### Linux kernel version (4.19 vs owLSM 5.14)

- **Your Tetragon sentence matches v1.6.1 FAQ verbatim intent:** FAQ states **minimum 4.19**, with strong caveats that **not all features** work on older kernels and **BTF** is effectively required for the CO-RE loading path described in the same document.  
- Comparing “Tetragon minimum doc version” to “owLSm supported version” is apples-to-oranges unless you also mention **feature gating** (LSM override, large programs, uprobes override arch limits, etc.).

---

## Missing angles (still inside “enforcement_rules / prevention” theme)

These are not mandatory for your article, but they are the usual reviewer replies:

1. **Policy mode & safety rails:** Tetragon separates **monitoring vs enforcement** modes (`policy-mode` / `tetra tp set-mode` flow in docs). If you pitch prevention, a serious buyer asks how accidental enforcement is controlled—one paragraph closes that gap.

2. **Override vs signal semantics:** Enforcement doc (`concepts/enforcement`) explains differences (signal may not abort in-flight work; override returns an error). Useful to show you understand Tetragon’s model, even if owLSM’s story differs.

3. **`NotifyEnforcer` path:** Documented workaround pattern when multi-kprobe attachment is limited—relevant when arguing “breadth of enforcement mechanisms”.

4. **Version drift:** Anything you cite from generic “Tetragon docs” on the web should be checked against **v1.6.1** tag (example: `matchParentBinaries` visibility in CRD differs from `main`).

5. **Architecture / distro limits on specific actions:** uprobe `Override` x86_64-only note on v1.6.1 is a good example of “docs promise ≠ universally true on every supported kernel/arch”.

---

## Bottom line

- **Strongest fixes:** (1) qualify “substring”, (2) fix absolute claims about **uprobe blocking** using v1.6.1’s own `Override` uprobe section with constraints, (3) replace “every hook” with **kernel- and feature-gated** language, (4) **re-verify parent-binary enforcement** claims against **v1.6.1** CRD (avoid importing `main`-only fields from MCP snippets), (5) soften Sigma “plug and play”.  
- **Strong as positioning with edits:** expressive selector DSL vs hook-centric YAML, kill-parent session remediation story, correlated multi-hook product experience for owLSM.

---

## References (pinned where possible)

- Tetragon v1.6.1 FAQ (kernel minimum, BTF caveats): `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/docs/content/en/docs/installation/faq.md`  
- Tetragon v1.6.1 selectors (operators, selector OR semantics, uprobe override): `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/docs/content/en/docs/concepts/tracing-policy/selectors.md`  
- Tetragon v1.6.1 `KProbeSelector` struct: `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/pkg/k8s/apis/cilium.io/v1alpha1/types.go`  
- Tetragon v1.6.1 process map layout (`pkey`, binary buffers): `https://raw.githubusercontent.com/cilium/tetragon/v1.6.1/bpf/lib/process.h`  
- Tetragon Docs MCP server in this workspace: `tetragon Docs` → `https://gitmcp.io/cilium/tetragon` (semantic doc search; cross-check tag when precise version matters).
