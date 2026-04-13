---
layout: default
title: owLSM vs Tetragon – Enforcement capabilities
parent: owLSM vs other projects
nav_order: 1
---

# owLSM vs Tetragon – Enforcement capabilities

Tetragon is a leading eBPF-based monitor with growing enforcement support. The owLSM maintainers have used it for years. this page is not meant to disparage Tetragon, but for showing how superior owLSM enforcement capabilities are.

**Compared versions:** owLSM **v0.2.0** and Tetragon **v1.6.1**.  
We cover **enforcement only**: what policies can block, which fields exist **at the decision point** (not full post-hoc event payloads) and what features do the prevention/enforcment policies offer.

## Glossary

| Term | Meaning |
|------|---------|
| **Enforcement / Prevention** | Block an action before it happens (inline event evaluation). |
| **Visibility / monitoring** | Observe what happened on the system (async events). |
| **Enforcement policy / Rules** | Yaml files that define what to block and what to allow. 
| **Event** | data about a specific operation that happened on the system. These come from the kernel and enriched in userspace before shown to the user. Event has data that wasn't available at the time of the enforcement decision. |

## What we compare

- Valuable features available in the enforcement policy.
- Data available to the enforcement policy and at the the enforcement point (when enforcement decisions are made).
- knowlege required to write an enforcement policy.

We **do not** score general observability or “nice” telemetry as we only focus on enforcement. Again, data that is available in the event, isn't always available at the time of the enforcement decision.

## Comparison table

Click on a row for details.


<style>
/* Comparison table colors (synthwave pink / indigo) */
.enforcement-cmp-wrap {
  margin: 1rem 0;
  --h1: #db2777;
  --h2: #6366f1;
  --hf: #ffffff;
  --bdr: #f9a8d4;
  --r-odd: #fdf2f8;
  --r-even: #eef2ff;
  --td-fg: #4c0519;
  --desc: #be185d;
  --hover: #fce7f3;
  --hover-bar: #db2777;
  --hover-ring: rgba(219, 39, 119, 0.4);
  --active: #fbcfe8;
  --focus: #6366f1;
  --shadow: 0 4px 26px rgba(219, 39, 119, 0.2);
}

.enforcement-cmp-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
  box-shadow: var(--shadow);
  line-height: 1.2;
  border-radius: 6px;
  overflow: hidden;
}
.enforcement-cmp-wrap .enforcement-cmp-table th,
.enforcement-cmp-wrap .enforcement-cmp-table td {
  text-align: center;
  vertical-align: middle;
  border: 1px solid var(--bdr);
  padding: 0.30rem 0.35rem;
  color: var(--td-fg);
}
.enforcement-cmp-wrap .enforcement-cmp-table thead th {
  background: linear-gradient(120deg, var(--h1), var(--h2));
  color: var(--hf);
  font-weight: 600;
  padding: 0.3rem 0.35rem;
  font-size: 0.8rem;
  text-shadow: 0 1px 1px rgba(0,0,0,0.12);
}
.enforcement-cmp-wrap .enforcement-cmp-table tbody tr:nth-child(odd) td {
  background: var(--r-odd);
}
.enforcement-cmp-wrap .enforcement-cmp-table tbody tr:nth-child(even) td {
  background: var(--r-even);
}
.cmp-row {
  cursor: pointer;
  transition: background-color 0.12s ease, box-shadow 0.12s ease, filter 0.12s ease;
}
.enforcement-cmp-wrap .cmp-row:hover td {
  background: var(--hover) !important;
  box-shadow: inset 3px 0 0 var(--hover-bar), inset 0 0 0 1px var(--hover-ring);
  filter: brightness(1.02);
}
.enforcement-cmp-wrap .cmp-row:active td {
  background: var(--active) !important;
}
.enforcement-cmp-wrap .cmp-row:focus {
  outline: 2px solid var(--focus);
  outline-offset: -2px;
}
.feat-wrap { display: block; text-align: center; margin: 0; padding: 0; }
.feat-title { display: block; margin: 0 0 0.06rem 0; padding: 0; line-height: 1.2; color: inherit; }
.feat-desc {
  display: block;
  font-size: 0.76em;
  color: var(--desc);
  font-weight: 400;
  line-height: 1.2;
  margin: 0;
  padding: 0;
}
.cmp-mid { white-space: normal; padding: 0.38rem 0.22rem; }
#cmp-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.45);
  z-index: 10000;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}
#cmp-modal-overlay.is-open { display: flex; }
#cmp-modal {
  background: #fff;
  max-width: 42rem;
  width: 100%;
  max-height: 85vh;
  overflow: auto;
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  box-shadow: 0 8px 32px rgba(0,0,0,0.2);
  position: relative;
}
#cmp-modal-close {
  position: absolute;
  top: 0.5rem;
  right: 0.65rem;
  border: none;
  background: transparent;
  font-size: 1.5rem;
  line-height: 1;
  cursor: pointer;
  color: #5f6368;
}
#cmp-modal-close:hover { color: #202124; }
#cmp-modal-body { margin-top: 0.5rem; line-height: 1.55; text-align: left; }
#cmp-modal-body code { background: #f1f3f4; padding: 0.1em 0.35em; border-radius: 4px; font-size: 0.9em; }
#cmp-modal-body a { word-break: break-word; }
</style>

<div class="enforcement-cmp-wrap">
<table class="enforcement-cmp-table">
  <thead>
    <tr>
      <th>Feature</th>
      <th>owLSM v0.2.0</th>
      <th>Tetragon v1.6.1</th>
    </tr>
  </thead>
    <tbody>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="0">
    <td><span class="feat-wrap"><strong class="feat-title">Simple string matching</strong><span class="feat-desc">Exact, prefix, suffix </span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">✅</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="1">
    <td><span class="feat-wrap"><strong class="feat-title">Substring matching</strong><span class="feat-desc">String contains</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="2">
    <td><span class="feat-wrap"><strong class="feat-title">Regex matching</strong></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="3">
    <td><span class="feat-wrap"><strong class="feat-title">Fieldref matching</strong><span class="feat-desc">Compare two runtime fields</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="4">
    <td><span class="feat-wrap"><strong class="feat-title">Mask matching</strong><span class="feat-desc">Bitwise AND on numeric values</span></span></td>
    <td class="cmp-mid">❌</td>
    <td class="cmp-mid">✅</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="5">
    <td><span class="feat-wrap"><strong class="feat-title">Basic conditions</strong><span class="feat-desc">Limited AND / OR</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">✅</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="6">
    <td><span class="feat-wrap"><strong class="feat-title">Complex conditions</strong><span class="feat-desc">AND, OR, NOT, parentheses, X of Y</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="7">
    <td><span class="feat-wrap"><strong class="feat-title">Match full process command line</strong><span class="feat-desc">Rules ability to match against full argv string</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="8">
    <td><span class="feat-wrap"><strong class="feat-title">Match on shell command</strong><span class="feat-desc">Rules ability to match against the shell command that triggered this operatrion</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="9">
    <td><span class="feat-wrap"><strong class="feat-title">Stateful enforcement</strong><span class="feat-desc">Correlate data across hooks</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="10">
    <td><span class="feat-wrap"><strong class="feat-title">Keyword matching</strong><span class="feat-desc">Search a string across all event fields</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="11">
    <td><span class="feat-wrap"><strong class="feat-title">Match original parent process</strong><span class="feat-desc">After reparenting, still target the original parent</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="12">
    <td><span class="feat-wrap"><strong class="feat-title">Rich process context</strong><span class="feat-desc">A lot of high-value process fields exposed to rules</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">⚠️</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="13">
    <td><span class="feat-wrap"><strong class="feat-title">Kill process as enforcement action</strong></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">✅</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="14">
    <td><span class="feat-wrap"><strong class="feat-title">Kill parent process as enforcement action</strong></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="15">
    <td><span class="feat-wrap"><strong class="feat-title">Broad kernel attach surface</strong><span class="feat-desc">All LSM's, kprobes with ALLOW_ERROR_INJECTION, etc'</span></span></td>
    <td class="cmp-mid">❌</td>
    <td class="cmp-mid">✅</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="16">
    <td><span class="feat-wrap"><strong class="feat-title">Kernel abstraction</strong><span class="feat-desc">Users need no kernel knowledge</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  <tr class="cmp-row" tabindex="0" role="button" aria-label="Show details" data-cmp-idx="17">
    <td><span class="feat-wrap"><strong class="feat-title">Standard rules language</strong><span class="feat-desc">use of a standard rules language</span></span></td>
    <td class="cmp-mid">✅</td>
    <td class="cmp-mid">❌</td>
  </tr>
  </tbody>
</table>
</div>

<div id="cmp-modal-overlay" aria-hidden="true">
  <div id="cmp-modal" role="dialog" aria-modal="true" aria-labelledby="cmp-modal-title">
    <button type="button" id="cmp-modal-close" aria-label="Close">&times;</button>
    <h2 id="cmp-modal-title" style="margin:0;font-size:1.05rem;line-height:1.3;padding-right:2rem;"></h2>
    <div id="cmp-modal-body"></div>
  </div>
</div>

<script id="cmp-comments-json" type="application/json">["Comparing the event string to the rule string.\nFor example: `if event.path == rule.path`\n\nThese three are the simple string comparisons most eBPF enforcement solutions offer.\nImplementing them is straightforward.\n\n**Equivalent in Sigma to:** `exactmatch`, `startswith`, `endswith`", "Checks whether the event string contains the rule string.\nFor example: `if event.path contains rule.path`\n\nThis is much harder to implement in eBPF because of verifier limitations.\nowLSM was the first open-source project to offer substring matching in eBPF.\n\n**Equivalent in Sigma to:** `contains`", "The rule value is a regex pattern that searches for a specific pattern in the event field.\nowLSM was the first open-source project to implement regex matching in eBPF.\n\n**Equivalent in Sigma to:** `re`", "The rule compares two different fields on the same event.\nThis is used when you need to check a relationship between two event fields at runtime.\nFor example: `if event.path == event.parent_cmd`\n\n**See docs:** cybereason-public.github.io/owLSM/rules/#field-reference-modifier", "The rule performs a bitwise AND on a numeric value from the event. For example: `if event.pid AND 5422 == 5422`\n\nowLSM does not support this because it is not part of the Sigma rules specification, and in practice it is unlikely to be needed often (if ever).", "A rule can check multiple fields of an event. Conditions let you combine checks with AND/OR.\nFor example: `if event.path == rule.path and event.uid > 0 or event.cmd == rule.cmd`\nHowever, these `and` / `or` conditions only add very basic logic; often that is not enough or not convenient.", "A rule can check multiple fields of an event. Complex conditions let you add whatever Boolean logic you need.\nWith them you can merge different rules, build a more efficient runtime evaluator, and more.\nFor example: `if event.path == rule.path and (event.cmd == rule.cmd or (event.uid > 0 and not event.ruid == 7) and event.pid != 1)`\nThe example shows only part of what conditions can express.\nTetragon does not support complex nested conditions; it supports only simple AND/OR.\nowLSM supports all the conditions in the sigma rule specs\n\n**See docs:** cybereason-public.github.io/owLSM/rules/#rule-condition", "Tetragon enforcement policies are stateless. They can only access data available directly in the hooked function. Things like current task members and function arguments (Tetragon does have a small process map, but it is of limited use in the current version).\nWith Tetragon you can manually access specific command-line arguments one by one, but you cannot obtain the full process command line as a single string and match rules against it.\nIf that is hard to believe, try it yourself: `git clone --branch v1.6.1 --depth 1 https://github.com/cilium/tetragon.git; grep -r \"action: Override\" tetragon/examples/`\nThose are the official example Tetragon enforcement policies. You will not see full command-line string matching there.\n\nowLSM does the heavy lifting: when it creates a process object it walks the process memory, extracts the full command line (argument by argument), stores it in a string and stores the string in one of its stateful process caches. That lets users write rules that match the full process command line as a single string.\nowLSM was the first open-source project to offer full command-line extraction and matching against it in eBPF.\n\n**See:** [owLSM full command-line construction in the kernel](https://github.com/Cybereason-Public/owLSM/blob/48ff2bd9d4c1c939219b93f9d63245fbd6f7b7dc/src/Kernel/struct_extractors.bpf.h#L15)\n", "Monitoring and blocking malicious shell commands has many complications. Here are a few.\n\n1. eBPF offers `uprobes` to attach to and monitor userspace programs (uprobes can influence userspace behavior as well, but with heavy constraints).\nShells run in userspace, so you cannot generally use eBPF to override their internal return values and thereby block the behavior end-to-end.\nYou still rely on LSM hooks to block the kernel-side effect—but LSM hooks do not see the userspace shell command string by themselves.\nThat means you need stateful eBPF programs that correlate data between uprobe hooks and LSM hooks.\nUprobe hooks record the shell command and store it in a map; when a related syscall runs, LSM hooks read the map and can evaluate `if event.shell_command == rule.shell_command then block`.\nTetragon is stateless and does not perform this correlation across its eBPF programs.\nowLSM takes a stateful approach and correlates data from uprobes and LSM hooks to enforce policy on the shell command.\nowLSM was the first open-source project to offer prevention based on shell commands in eBPF, because it correlates this data (and addresses the other shell monitoring problems).\n\n2. Hooking bash and recording the shell command is easy. It is a single uprobe on the `bash:readline` function, because bash exports the `readline` symbol, which returns the full command the user typed.\nDash (the default shell on Ubuntu, Debian, Mint, …) is different:\n- Unlike bash, dash does not export any symbol.\n- Unlike readline-based shells, dash has no single function that returns or stores the full command the user typed. Its needs to be reconstructed\n\nowLSM uses several techniques to support dash and zsh.\nIt was also the first open-source project to monitor dash commands reliably. A full explanation is too long for this box; see [this deep dive](https://cybereason-public.github.io/owLSM/architecture/shell-commands.html).", "Tetragon lets you choose which function to hook; the data you can read is limited to what that hook exposes (arguments, current task, and so on).\nOften that is not enough because the hook lacks important context.\nowLSM hides the hook from the user and chains multiple hooks, correlating data between them so users get a stateful enforcement experience.\nFor example, `on_exec.bpf.c` uses three LSM hooks to collect everything needed for exec (old process, new process, parent).\n`on_tcp_incomming.bpf.c` requires correlating two different hooks to have the full connection picture (source IP, destination IP, source port, destination port, and so on) at the prevention decision point.\n\nTetragon does maintain some maps for limited state, but they are minimal and don't carry almost any data", "You have a specific string you want to find in the event. You may not know which field it will appear in (or you may not care).\nWith keyword matching, owLSM can search for one or more strings across all event members instead of naming specific fields.\n\n**See docs:** cybereason-public.github.io/owLSM/rules/#rule-selection", "The parent process can change on Linux. When a parent exits, the child is reparented (almost always to PID 1).\nMany malware samples spawn a malicious child and then exit, so inline security tools only see the new parent, not the original parent (the orchestrator).\nWhen authors write rules about the parent, they usually care about the original parent, not PID 1.\nThat requires stateful eBPF: a cache of exited parents that still matter to alive children.\n\nowLSM maintains multiple process caches for scenarios like this. When a rule refers to the parent process, it refers to the original parent, not the reparented one if the original exited.\n\nTetragon is stateless; for parent fields you use `task.real_parent` or `mm.owner.real_parent`, which refer to the *current* parent, not the original parent. See Tetragon TracingPolicy / enforcement examples for how parent fields behave.", "Rich is subjective.\nStill, if you compare how many **useful** process fields you can match on in owLSM rules versus Tetragon enforcement policies, the gap is large.\nowLSM exposes many high-value process fields (binary path, command line, SUID state, ptrace flags, and more).\nTetragon exposes mostly basic process fields (PID, binary path, namespace metadata, capabilities). You can walk some kernel structures for extra scalars values, but that is inconvenient, can vary across kernel versions, and still does not give you fields like the full command line or correlated shell input.\n\nThat is another reason owLSM rules are stronger than Tetragon’s enforcement policy: the set of matchable process fields is substantially larger.\n\n**See all process fields owLSM rules can match:** cybereason-public.github.io/owLSM/rules/#available-fields", "Both projects let you kill the process that performed the malicious operation as an enforcement action.", "Malicious processes/sessions often run helper binaries (`chmod`, `curl`, and similar). Rules that only kill the process performing the syscall therefore tend to kill the helper, while the interactive shell or orchestrator process survives.\nThat is why owLSM can deny the operation, kill the acting process, and kill the parent together.\nTetragon can deny the operation and kill the acting process, but it cannot kill the parent process.\n\nowLSM does this conservatively: it only attempts to kill the parent when it is still the *original* parent and is not PID 1.", "owLSM abstracts attach points: it exposes a curated set of monitored events (and that set keeps growing).\nowLSM still lacks some hook types, but it covers the most important ones for security teams.\n\nTetragon gives you freedom to hook any kernel function, including ones with prevention semantics, so you can in principle observe and enforce very broadly.\nTetragon can also enforce some userspace behavior under tight constraints—something owLSM is not likely to add soon.", "Tetragon enforcement policies require knowledge of the kernel, and specifically of the exact kernel you run.\nYou need to know which functions or syscalls to watch, what their arguments mean, how structures are laid out, and so on. That is what gives Tetragon its flexibility, and it is the main weakness for anyone who is not a kernel specialist.\n\nowLSM completely abstracts the kernel. Users work with event names such as `WRITE`, `FILE_CREATE`, `EXEC`, `CHMOD`, and similar.\nKernel and eBPF details stay hidden.\nThat is less flexible, but it enables owLSM’s greatest strength—stateful rules—because the agent wires multiple hooks together and correlates data behind the scenes.", "Sigma is the de facto standard rules language for security content.\nUsers do not have to learn a proprietary dialect, and importing community rules is practical (for example from SigmaHQ for Linux, with small adaptations).\n\nTetragon enforcment uses its own CRD-based “language,” which assumes Linux-kernel literacy.\nImporting third-party rule packs (such as SigmaHQ) into Tetragon is effectively impractical.\n\nThat is why Sigma support mattered to us: it makes users lives easier and gives them stronger tooling."]</script>
<script>
(function () {
  var comments = JSON.parse(document.getElementById('cmp-comments-json').textContent);
  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function commentToHtml(raw) {
    if (!raw) return '<p><em>(No comment)</em></p>';
    var s = raw;
    var out = '';
    var i = 0;
    while (i < s.length) {
      var bk = s.indexOf('**', i);
      if (bk === -1) { out += escapeHtml(s.slice(i)); break; }
      out += escapeHtml(s.slice(i, bk));
      var bk2 = s.indexOf('**', bk + 2);
      if (bk2 === -1) { out += escapeHtml(s.slice(bk)); break; }
      out += '<strong>' + escapeHtml(s.slice(bk + 2, bk2)) + '</strong>';
      i = bk2 + 2;
    }
    s = out;
    out = '';
    i = 0;
    while (i < s.length) {
      var bt = s.indexOf('`', i);
      if (bt === -1) { out += s.slice(i); break; }
      out += s.slice(i, bt);
      var bt2 = s.indexOf('`', bt + 1);
      if (bt2 === -1) { out += s.slice(bt); break; }
      out += '<code>' + escapeHtml(s.slice(bt + 1, bt2)) + '</code>';
      i = bt2 + 1;
    }
    s = out;
    s = s.replace(/\[([^\]]+)\]\(([^)]*)\)/g, function (_, text, url) {
      var u = url.trim();
      if (u && !/^https?:\/\//i.test(u)) u = 'https://' + u;
      return '<a href="' + escapeHtml(u) + '" target="_blank" rel="noopener">' + escapeHtml(text) + '</a>';
    });
    s = s.replace(/(^|[\s>])((https?:\/\/|www\.)[^\s<]+)/gi, function (_, p, url) {
      var u = url.replace(/[),.;]+$/, '');
      var href = u.indexOf('http') === 0 ? u : 'https://' + u;
      return p + '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' + escapeHtml(u) + '</a>';
    });
    s = s.replace(/\n/g, '<br>\n');
    return '<p>' + s + '</p>';
  }
  var overlay = document.getElementById('cmp-modal-overlay');
  var body = document.getElementById('cmp-modal-body');
  var titleEl = document.getElementById('cmp-modal-title');
  var closeBtn = document.getElementById('cmp-modal-close');
  function ensureLinksNewTab(root) {
    root.querySelectorAll('a[href]').forEach(function (a) {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
    });
  }
  function openModal(idx, row) {
    var ft = row && row.querySelector('.feat-title');
    titleEl.textContent = ft ? ft.textContent.trim() : 'Details';
    body.innerHTML = commentToHtml(comments[idx] || '');
    ensureLinksNewTab(body);
    overlay.classList.add('is-open');
    overlay.setAttribute('aria-hidden', 'false');
    closeBtn.focus();
  }
  function closeModal() {
    overlay.classList.remove('is-open');
    overlay.setAttribute('aria-hidden', 'true');
    body.innerHTML = '';
    titleEl.textContent = '';
  }
  document.querySelectorAll('.cmp-row').forEach(function (row) {
    row.setAttribute('title', 'Click for details');
    row.addEventListener('click', function () {
      openModal(parseInt(row.getAttribute('data-cmp-idx'), 10), row);
    });
    row.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openModal(parseInt(row.getAttribute('data-cmp-idx'), 10), row);
      }
    });
  });
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('is-open')) closeModal();
  });
})();
</script>
