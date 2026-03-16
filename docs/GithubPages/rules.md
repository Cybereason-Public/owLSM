---
layout: default
title: Rules
nav_order: 4
permalink: /rules/
---

# Rules

owLSM rules are sigma-like rules.  
We are trying to support as many sigma rules features as possible, especially in the detection part. Actively aligning owLSM rules with sigma rules.  
<br>
In order to fully understand the owLSM rules, we strongly advise to read [sigma-rules-specification detection section](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#detection) first.

## Rule Examples

For more examples, see [`Rules/RuleExamples`](https://github.com/cybereason-labs/owLSM/tree/main/Rules/RuleExamples)  

<div class="tab-container">
  <div class="tab-buttons">
    <button class="tab-button active" data-tab="simple">Simple Example</button>
    <button class="tab-button" data-tab="complex">Network Example</button>
    <button class="tab-button" data-tab="multievent">Multi-Event Example</button>
  </div>
  
  <div id="simple" class="tab-content active">
    <div class="interactive-code">
<pre><code><a href="#rule-id" class="code-link">id</a>: 1
<a href="#rule-description" class="code-link">description</a>: "Block curl from reading SSH keys"
<a href="#rule-min-version" class="code-link">min_version</a>: "1.0.0"
<a href="#rule-max-version" class="code-link">max_version</a>: "2.0.0"
<a href="#rule-action" class="code-link">action</a>: "BLOCK_EVENT"
<a href="#rule-events" class="code-link">events</a>:
    - READ
<a href="#rule-detection" class="code-link">detection</a>:
    <a href="#rule-selection" class="code-link">selection</a>:
        target.file.path|contains: ".ssh"
        process.file.filename: "curl"
    <a href="#rule-condition" class="code-link">condition</a>: selection</code></pre>
    </div>
  </div>
  
  <div id="complex" class="tab-content">
    <div class="interactive-code">
<pre><code><a href="#rule-id" class="code-link">id</a>: 200
<a href="#rule-description" class="code-link">description</a>: "Block suspicious outbound connections to known C2 patterns"
<a href="#rule-action" class="code-link">action</a>: "BLOCK_KILL_PROCESS"
<a href="#rule-events" class="code-link">events</a>:
    - NETWORK
<a href="#rule-detection" class="code-link">detection</a>:
    <a href="#rule-selection" class="code-link">selection_outbound</a>:
        network.direction: "OUTGOING"
    <a href="#rule-selection" class="code-link">selection_suspicious_ports</a>:
        network.destination_port:
            - 4444
            - 5555
            - 6666
    <a href="#rule-selection" class="code-link">selection_suspicious_process</a>:
        process.file.filename|endswith:
            - ".sh"
            - "python"
            - "perl"
            - "ruby"
    <a href="#rule-selection" class="code-link">selection_internal_ranges</a>:
        network.destination_ip|cidr:
            - "212.0.0.0/8"
            - "2607:f8b0:4000::/36"
            - "2001:0db8:85a3:0000:0000:8a2e:0370:0000/112"
    <a href="#rule-selection" class="code-link">filter_known_good</a>:
        process.file.path|startswith:
            - "/usr/bin/apt"
            - "/usr/bin/dnf"
            - "/usr/bin/yum"
        process.euid: 0
    <a href="#rule-condition" class="code-link">condition</a>: selection_outbound and (selection_suspicious_ports or selection_internal_ranges) and selection_suspicious_process and not filter_known_good</code></pre>
    </div>
  </div>
  
  <div id="multievent" class="tab-content">
    <div class="interactive-code">
<pre><code><a href="#rule-id" class="code-link">id</a>: 50
<a href="#rule-description" class="code-link">description</a>: "Block suspicious access to /etc/passwd from processes in /tmp"
<a href="#rule-action" class="code-link">action</a>: "BLOCK_KILL_PROCESS"
<a href="#rule-events" class="code-link">events</a>:
    - CHMOD
    - CHOWN
    - READ
    - WRITE
<a href="#rule-detection" class="code-link">detection</a>:
    <a href="#rule-selection" class="code-link">selection_target</a>:
        target.file.path: "/etc/passwd"
    <a href="#rule-selection" class="code-link">selection_process_in_tmp</a>:
        process.file.path|startswith: "/tmp"
    <a href="#rule-selection" class="code-link">selection_parent_in_tmp</a>:
        parent_process.file.path|startswith: "/tmp"
    <a href="#rule-condition" class="code-link">condition</a>: selection_target and (selection_process_in_tmp or selection_parent_in_tmp)</code></pre>
    </div>
  </div>
  
</div>

---

## Rule Components

<h3 id="rule-id" class="section-anchor">
  <span class="section-path">id</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> Integer (1 - 65535)</p>
</div>

Unique identifier for the rule. Must be unique across all loaded rules.<br>
The rule ID determines the evaluation order when matching rules against events. Rules with lower IDs are evaluated first (e.g., rule 1 is evaluated before rule 7).<br>
Rule matching stops at the first match. If rule 1 matches an event, rule 2 and subsequent rules are not evaluated, and the event is handled according to rule 1's action.<br>
This behavior differs from most Sigma engines, which process all rules and accumulate actions. However, this first-match approach is significantly more efficient, which is critical for inline syscall monitoring.
</div>

<h3 id="rule-description" class="section-anchor">
  <span class="section-path">description</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> String</p>
</div>

Human-readable description of what the rule detects.<br>
This is included in the event output when the rule matches.
</div>

<h3 id="rule-action" class="section-anchor">
  <span class="section-path">action</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> <code>"ALLOW_EVENT"</code>, <code>"BLOCK_EVENT"</code>, <code>"BLOCK_KILL_PROCESS"</code>, <code>"BLOCK_KILL_PROCESS_KILL_PARENT"</code>, <code>"KILL_PROCESS"</code>, <code>"EXCLUDE_EVENT"</code></p>
</div>

Action owLSM will take when the rule matches.<br>
<br>
<strong>ALLOW_EVENT</strong> - Do nothing. Event is sent normally.<br>
<strong>BLOCK_EVENT</strong> - Blocks syscall/operation.<br>
<strong>BLOCK_KILL_PROCESS</strong> - Block the event and terminate the process that performed the action.<br>
<strong>BLOCK_KILL_PROCESS_KILL_PARENT</strong> - Block the event and terminate the process that performed the action and its parent.<br>
<strong>KILL_PROCESS</strong> - Don't blocked the event but terminate the process that performed the action.<br>
<strong>EXCLUDE_EVENT</strong> - Don't send the event. Good for reducing unwanted noise.!
</div>

<h3 id="rule-events" class="section-anchor">
  <span class="section-path">events</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> Array of: <code>"CHMOD"</code>, <code>"CHOWN"</code>, <code>"READ"</code>, <code>"WRITE"</code>, <code>"UNLINK"</code>, <code>"FILE_CREATE"</code>, <code>"MKDIR"</code>, <code>"RMDIR"</code>, <code>"EXEC"</code>, <code>"RENAME"</code>, <code>"NETWORK"</code></p>
</div>

Event types this rule applies to.<br>
A rule can be applied to one or more event types. See `Multi-Event Example` at the top.<br>
<br>
<strong>EXEC</strong> - rules for exec events.<br>
<strong>CHMOD</strong> - rules for chmod events.<br>
<strong>CHOWN</strong> - rules for chown events.<br>
<strong>READ</strong> - rules for read events. Only on regular files and symlinks.<br>
<strong>WRITE</strong> - rules for write events. Only on regular files and symlinks.<br>
<strong>UNLINK</strong> - rules for unlink events (file deletion).<br>
<strong>FILE_CREATE</strong> - rules for file creation events.<br>
<strong>MKDIR</strong> - rules for directory creation events.<br>
<strong>RMDIR</strong> - rules for directory deletion events.<br>
<strong>RENAME</strong> - rules for file renaming events (moving a file).<br>
<strong>NETWORK</strong> - rules for network related events. Currently TCP connection only.<br>
<br>
The fields that you use in a rule must correspond to the event types you specified.<br>
If you specified both CHMOD and CHOWN, you can't use the field chmod.requested_mode as it corresponds only to CHMOD but not to CHOWN.<br>
This will become more clear after you read the `Available Fields` part.
</div>

<h3 id="rule-min-version" class="section-anchor">
  <span class="section-path">min_version</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Options:</strong> String in semantic version format (X.Y.Z)</p>
</div>

Minimum owLSM version required for this rule to be loaded.<br>
If the running owLSM version is below this value, the rule will be skipped during loading.<br><br>

<strong>Format:</strong> <code>"MAJOR.MINOR.PATCH"</code> (e.g., <code>"1.0.0"</code>, <code>"2.5.10"</code>)<br>
Leading zeros are not allowed (e.g., <code>"01.0.0"</code> is invalid).
</div>

<h3 id="rule-max-version" class="section-anchor">
  <span class="section-path">max_version</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Options:</strong> String in semantic version format (X.Y.Z)</p>
</div>

Maximum owLSM version for this rule to be loaded.<br>
If the running owLSM version is above this value, the rule will be skipped during loading.<br><br>

<strong>Format:</strong> <code>"MAJOR.MINOR.PATCH"</code> (e.g., <code>"1.0.0"</code>, <code>"2.5.10"</code>)<br>
Leading zeros are not allowed (e.g., <code>"01.0.0"</code> is invalid).
</div>

<h3 id="rule-detection" class="section-anchor">
  <span class="section-path">detection</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> Object containing selections and condition</p>
</div>

Just like <a href="https://sigmahq.io/docs/basics/rules.html#detection">standard Sigma rules detection</a>, the detection section defines the matching criteria for the rule.<br>
It contains one or more named selections and a condition that combines them.
</div>

<h3 id="rule-selection" class="section-anchor">
  <span class="section-path">selection</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true (at least one selection)</p>
<p><strong>Options:</strong> Named object with field conditions</p>
</div>

Just like <a href="https://sigmahq.io/docs/basics/rules.html#selections">standard Sigma rules selection</a>, selections define matching criteria.<br>
Each selection is a named group that organizes detections for readability and filtering.<br><br>

<strong>AND / OR Logic:</strong><br>
Sigma uses YAML structure to represent logical operations:<br>
• <strong>AND logic:</strong> Multiple fields within a selection (dictionary/object syntax)<br>
• <strong>OR logic:</strong> Multiple values for a single field (list syntax)<br><br>

Selection names can be any valid identifier (e.g., <code>selection</code>, <code>selection_files</code>, <code>filter_allowed</code>).<br>
<strong>Example with multiple values (OR logic):</strong>
<div class="interactive-code">
<pre><code>selection:
    process.file.filename|endswith:
        - ".sh"
        - ".py"
        - ".pl"</code></pre>
</div>
 <br><br>
<strong>Keywords (field-less selection):</strong><br>
Keywords are a special type of search where you don't specify a field name.<br>
Using keyword, we can search for a string across all the <strong>event string fields</strong>.<br>
This is useful for broad searches when we don't want to target a specific field.<br>
<div class="interactive-code">
<pre><code># OR logic - match ANY keyword in ANY string field
keywords:
    - "malware"
    - "*.evil.com"

# AND logic - ALL keywords must match (can be in different fields)
keywords|all:
    - "admin"
    - "/etc/shadow"</code></pre>
</div>

<strong>Keyword limitations:</strong><br>
• Keywords expand to all string fields, which impacts performance<br>
• Same wildcard rules apply as string modifiers<br>
• Cannot be used with field-specific modifiers like <code>cidr</code>
• Tule token max is reached very easily when using keywords.
</div>

<h3 id="rule-condition" class="section-anchor">
  <span class="section-path">condition</span>
</h3>

<div class="rule-section">
<div class="field-meta">
<p><strong>Required:</strong> true</p>
<p><strong>Options:</strong> Boolean expression combining selections</p>
</div>

The condition combines selections using boolean operators.<br>
This what actually determines the logic of the rule.<br><br>

<strong>Operators:</strong><br>
• <code>and</code> - Both must match<br>
• <code>or</code> - Either must match<br>
• <code>not</code> - Negation<br>
• Parentheses <code>()</code> for grouping<br><br>

<strong>Special Conditions:</strong><br>
• <code>1 of selection_*</code> - Match any one selection with that prefix<br>
• <code>all of selection_*</code> - Match all selections with that prefix<br>
• <code>X of them</code> - Match at least X of all defined selections<br>
• <code>X of selection_*</code> - Match at least X selections with that prefix (e.g., <code>2 of selection_*</code>)<br><br>

<strong>Limitations:</strong><br>
• Maximum 128 tokens per rule expression (<code>MAX_TOKENS_PER_RULE</code>)<br><br>

<strong>Examples:</strong>
<div class="interactive-code">
<pre><code># Simple
condition: selection

# Multiple selections
condition: selection_files and selection_process

# With negation (whitelist filter)
condition: selection_target and not filter_allowed

# Complex grouping
condition: (selection_a or selection_b) and selection_c and not filter

# X of patterns
condition: 2 of them
condition: 1 of selection_*
condition: 3 of selection_suspicious_*</code></pre>
</div>
</div>

---

## Available Modifiers

Modifiers specify how field values are compared.

### String Modifiers

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `exactmatch` | `field: "value"` | Exact string match (default) |
| `contains` | `field|contains: "value"` | Substring match |
| `startswith` | `field|startswith: "value"` | Prefix match |
| `endswith` | `field|endswith: "value"` | Suffix match |

**Limitation:** Rule string values are capped at 32 characters.

### Negation Modifier

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `neq` | `field|neq: "value"` | Not equal — true when the field does **not** equal the value |

`neq` only accepts a **single scalar value** (not a list) and **cannot be combined** with any other modifier or quantifier.

<div class="interactive-code">
<pre><code>detection:
    sel_not_target:
        target.file.path|neq: "/etc/target.txt"
    sel_not_root:
        process.euid|neq: 0
    condition: sel_not_target and sel_not_root</code></pre>
</div>

### Numeric Modifiers

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `equal` | `field: value` | Exact numeric match (default) |
| `above` / `gt` | `field|gt: value` | Greater than |
| `below` / `lt` | `field|lt: value` | Less than |
| `equal_above` / `gte` | `field|gte: value` | Greater than or equal |
| `equal_below` / `lte` | `field|lte: value` | Less than or equal |

### Network Modifiers

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `cidr` | `field|cidr: "10.0.0.0/8"` | CIDR network match for IP addresses |

### Quantifier Modifier

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `all` | `field|all: [values]` | All values must match (AND logic instead of default OR) |

By default, when a field has multiple values (list), any one match is sufficient (OR logic). The `all` modifier changes this to require **all** values to match (AND logic).<br>
Can be combined with string modifiers like `contains`, `startswith`, `endswith`.

<div class="interactive-code">
<pre><code>detection:
    sel:
        process.cmd|contains|all:
            - "sudo"
            - "rm"
    condition: sel</code></pre>
</div>

### Field Reference Modifier

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `fieldref` | `field|fieldref: "other_field"` | Compare one field against another field at runtime |

The `fieldref` modifier compares a field against the **runtime value of another field**, instead of a static value. The value must be a single valid field name.<br>
Both fields must be the same type (both string, both numeric, or both enum).<br>

**Supported fieldref combinations:**<br>
• String fields: can be combined with `startswith` or `endswith`<br>
• Numeric fields: can be combined with all numeric modifiers<br>
• Enum fields: no additional modifiers supported (only exact match or `neq`)<br>
• Cannot be combined with `all`, `cidr`, or IP fields<br>

<div class="interactive-code">
<pre><code>detection:
    sel_filename:
        target.file.path|fieldref|endswith: process.file.filename
    sel_same_uid:
        process.ruid|fieldref: process.euid
    condition: sel_filename and sel_same_uid</code></pre>
</div>

### Placeholder Expansion Modifier

| Modifier | Syntax | Description |
|----------|--------|-------------|
| `expand` | `field|expand: "%placeholder%"` | Expand a placeholder to a list of values at rule generation time |

The `expand` modifier enables **conversion-time placeholders**. Values wrapped in `%name%` are replaced with a list of concrete values from a placeholder definitions file during rule generation.<br>
This lets you maintain shared value lists (e.g., critical paths, admin users) in a single file and reference them across many rules.<br>

**Placeholder file format** (YAML):
<div class="interactive-code">
<pre><code># placeholder_values.yml
critical_paths:
    - "/etc/shadow"
    - "/etc/passwd"
    - "/etc/sudoers"
shells:
    - "bash"
    - "zsh"</code></pre>
</div>

**Rule using placeholders:**
<div class="interactive-code">
<pre><code>detection:
    sel_path:
        target.file.path|expand: "%critical_paths%"
    sel_shell:
        process.file.filename|contains|expand: "%shells%"
    condition: sel_path and sel_shell</code></pre>
</div>

Can be combined with string modifiers and the `all` quantifier.<br>

---

## Available Fields

Fields are the rule attributes that match against event attributes.<br>
Each field has a type (`string`, `numeric`, `ip`, or `enum`) that determines which modifiers can be used.<br>
Some fields are available for all events, while others are specific to certain event types.<br>

<details class="field-dropdown">
<summary><strong>Process Fields</strong> — The process that triggered the event</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>ALL</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>process.pid</code></td><td>numeric</td><td>Process ID</td></tr>
<tr><td><code>process.ppid</code></td><td>numeric</td><td>Parent process ID</td></tr>
<tr><td><code>process.ruid</code></td><td>numeric</td><td>Real user ID</td></tr>
<tr><td><code>process.rgid</code></td><td>numeric</td><td>Real group ID</td></tr>
<tr><td><code>process.euid</code></td><td>numeric</td><td>Effective user ID</td></tr>
<tr><td><code>process.egid</code></td><td>numeric</td><td>Effective group ID</td></tr>
<tr><td><code>process.suid</code></td><td>numeric</td><td>SUID</td></tr>
<tr><td><code>process.ptrace_flags</code></td><td>numeric</td><td>Ptrace flags</td></tr>
<tr><td><code>process.cmd</code></td><td>string</td><td>Command line arguments</td></tr>
<tr><td><code>process.shell_command</code></td><td>string</td><td><strong>(Beta)</strong> Shell command typed in an interactive session. See <a href="/owLSM/architecture/shell-commands/">Shell Commands</a></td></tr>
<tr><td><code>process.file.path</code></td><td>string</td><td>Executable full path</td></tr>
<tr><td><code>process.file.filename</code></td><td>string</td><td>Executable filename</td></tr>
<tr><td><code>process.file.owner.uid</code></td><td>numeric</td><td>Executable owner UID</td></tr>
<tr><td><code>process.file.owner.gid</code></td><td>numeric</td><td>Executable owner GID</td></tr>
<tr><td><code>process.file.mode</code></td><td>numeric</td><td>Executable permissions</td></tr>
<tr><td><code>process.file.suid</code></td><td>numeric</td><td>Executable SUID bit</td></tr>
<tr><td><code>process.file.sgid</code></td><td>numeric</td><td>Executable SGID bit</td></tr>
<tr><td><code>process.file.nlink</code></td><td>numeric</td><td>Executable hard link count</td></tr>
<tr><td><code>process.file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Executable file type</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>Parent Process Fields</strong> — The parent of the process that triggered the event</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>ALL</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>parent_process.pid</code></td><td>numeric</td><td>Parent process ID</td></tr>
<tr><td><code>parent_process.ppid</code></td><td>numeric</td><td>Grandparent process ID</td></tr>
<tr><td><code>parent_process.ruid</code></td><td>numeric</td><td>Real user ID</td></tr>
<tr><td><code>parent_process.rgid</code></td><td>numeric</td><td>Real group ID</td></tr>
<tr><td><code>parent_process.euid</code></td><td>numeric</td><td>Effective user ID</td></tr>
<tr><td><code>parent_process.egid</code></td><td>numeric</td><td>Effective group ID</td></tr>
<tr><td><code>parent_process.suid</code></td><td>numeric</td><td>SUID</td></tr>
<tr><td><code>parent_process.ptrace_flags</code></td><td>numeric</td><td>Ptrace flags</td></tr>
<tr><td><code>parent_process.cmd</code></td><td>string</td><td>Command line arguments</td></tr>
<tr><td><code>parent_process.shell_command</code></td><td>string</td><td><strong>(Beta)</strong> Shell command typed in an interactive session. See <a href="/owLSM/architecture/shell-commands/">Shell Commands</a></td></tr>
<tr><td><code>parent_process.file.path</code></td><td>string</td><td>Executable full path</td></tr>
<tr><td><code>parent_process.file.filename</code></td><td>string</td><td>Executable filename</td></tr>
<tr><td><code>parent_process.file.owner.uid</code></td><td>numeric</td><td>Executable owner UID</td></tr>
<tr><td><code>parent_process.file.owner.gid</code></td><td>numeric</td><td>Executable owner GID</td></tr>
<tr><td><code>parent_process.file.mode</code></td><td>numeric</td><td>Executable permissions</td></tr>
<tr><td><code>parent_process.file.suid</code></td><td>numeric</td><td>Executable SUID bit</td></tr>
<tr><td><code>parent_process.file.sgid</code></td><td>numeric</td><td>Executable SGID bit</td></tr>
<tr><td><code>parent_process.file.nlink</code></td><td>numeric</td><td>Executable hard link count</td></tr>
<tr><td><code>parent_process.file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Executable file type</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>Target File Fields</strong> — The file that the action is performed on</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>CHMOD</code>, <code>CHOWN</code>, <code>READ</code>, <code>WRITE</code>, <code>UNLINK</code>, <code>FILE_CREATE</code>, <code>MKDIR</code>, <code>RMDIR</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>target.file.path</code></td><td>string</td><td>Target file full path</td></tr>
<tr><td><code>target.file.filename</code></td><td>string</td><td>Target filename</td></tr>
<tr><td><code>target.file.owner.uid</code></td><td>numeric</td><td>Target file owner UID</td></tr>
<tr><td><code>target.file.owner.gid</code></td><td>numeric</td><td>Target file owner GID</td></tr>
<tr><td><code>target.file.mode</code></td><td>numeric</td><td>Target file permissions</td></tr>
<tr><td><code>target.file.suid</code></td><td>numeric</td><td>Target file SUID bit</td></tr>
<tr><td><code>target.file.sgid</code></td><td>numeric</td><td>Target file SGID bit</td></tr>
<tr><td><code>target.file.nlink</code></td><td>numeric</td><td>Target file hard link count</td></tr>
<tr><td><code>target.file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Target file type</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>Target Process Fields</strong> — The target process of the event</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>EXEC</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>target.process.pid</code></td><td>numeric</td><td>Target process ID</td></tr>
<tr><td><code>target.process.ppid</code></td><td>numeric</td><td>Target parent process ID</td></tr>
<tr><td><code>target.process.ruid</code></td><td>numeric</td><td>Real user ID</td></tr>
<tr><td><code>target.process.rgid</code></td><td>numeric</td><td>Real group ID</td></tr>
<tr><td><code>target.process.euid</code></td><td>numeric</td><td>Effective user ID</td></tr>
<tr><td><code>target.process.egid</code></td><td>numeric</td><td>Effective group ID</td></tr>
<tr><td><code>target.process.suid</code></td><td>numeric</td><td>SUID</td></tr>
<tr><td><code>target.process.ptrace_flags</code></td><td>numeric</td><td>Ptrace flags</td></tr>
<tr><td><code>target.process.cmd</code></td><td>string</td><td>Command line arguments</td></tr>
<tr><td><code>target.process.shell_command</code></td><td>string</td><td><strong>(Beta)</strong> Shell command typed in an interactive session. See <a href="/owLSM/architecture/shell-commands/">Shell Commands</a></td></tr>
<tr><td><code>target.process.file.path</code></td><td>string</td><td>Executable full path</td></tr>
<tr><td><code>target.process.file.filename</code></td><td>string</td><td>Executable filename</td></tr>
<tr><td><code>target.process.file.owner.uid</code></td><td>numeric</td><td>Executable owner UID</td></tr>
<tr><td><code>target.process.file.owner.gid</code></td><td>numeric</td><td>Executable owner GID</td></tr>
<tr><td><code>target.process.file.mode</code></td><td>numeric</td><td>Executable permissions</td></tr>
<tr><td><code>target.process.file.suid</code></td><td>numeric</td><td>Executable SUID bit</td></tr>
<tr><td><code>target.process.file.sgid</code></td><td>numeric</td><td>Executable SGID bit</td></tr>
<tr><td><code>target.process.file.nlink</code></td><td>numeric</td><td>Executable hard link count</td></tr>
<tr><td><code>target.process.file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Executable file type</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>Network Fields</strong> — Network connection fields</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>NETWORK</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>network.source_ip</code></td><td>string</td><td>Source IP address</td></tr>
<tr><td><code>network.source_port</code></td><td>numeric</td><td>Source port number</td></tr>
<tr><td><code>network.destination_ip</code></td><td>string</td><td>Destination IP address</td></tr>
<tr><td><code>network.destination_port</code></td><td>numeric</td><td>Destination port number</td></tr>
<tr><td><code>network.direction</code></td><td>enum <a href="#enum-connection-direction" class="code-link"><code>CONNECTION_DIRECTION</code></a></td><td>Connection direction</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>CHMOD Event Fields</strong> — chmod specific fields</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>CHMOD</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>chmod.requested_mode</code></td><td>numeric</td><td>Requested permission mode</td></tr>
</tbody>
</table>
</div>
</details>

<details class="field-dropdown">
<summary><strong>RENAME Event Fields</strong> — File rename source and destination fields</summary>
<div class="field-content">
<p class="event-badge"><strong>Available for events:</strong> <code>RENAME</code></p>

<table class="fields-table">
<thead>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>rename.source_file.path</code></td><td>string</td><td>Source file full path</td></tr>
<tr><td><code>rename.source_file.filename</code></td><td>string</td><td>Source filename</td></tr>
<tr><td><code>rename.source_file.owner.uid</code></td><td>numeric</td><td>Source file owner UID</td></tr>
<tr><td><code>rename.source_file.owner.gid</code></td><td>numeric</td><td>Source file owner GID</td></tr>
<tr><td><code>rename.source_file.mode</code></td><td>numeric</td><td>Source file permissions</td></tr>
<tr><td><code>rename.source_file.suid</code></td><td>numeric</td><td>Source file SUID bit</td></tr>
<tr><td><code>rename.source_file.sgid</code></td><td>numeric</td><td>Source file SGID bit</td></tr>
<tr><td><code>rename.source_file.nlink</code></td><td>numeric</td><td>Source file hard link count</td></tr>
<tr><td><code>rename.source_file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Source file type</td></tr>
<tr><td><code>rename.destination_file.path</code></td><td>string</td><td>Destination file full path</td></tr>
<tr><td><code>rename.destination_file.filename</code></td><td>string</td><td>Destination filename</td></tr>
<tr><td><code>rename.destination_file.owner.uid</code></td><td>numeric</td><td>Destination file owner UID</td></tr>
<tr><td><code>rename.destination_file.owner.gid</code></td><td>numeric</td><td>Destination file owner GID</td></tr>
<tr><td><code>rename.destination_file.mode</code></td><td>numeric</td><td>Destination file permissions</td></tr>
<tr><td><code>rename.destination_file.suid</code></td><td>numeric</td><td>Destination file SUID bit</td></tr>
<tr><td><code>rename.destination_file.sgid</code></td><td>numeric</td><td>Destination file SGID bit</td></tr>
<tr><td><code>rename.destination_file.nlink</code></td><td>numeric</td><td>Destination file hard link count</td></tr>
<tr><td><code>rename.destination_file.type</code></td><td>enum <a href="#enum-file-type" class="code-link"><code>FILE_TYPE</code></a></td><td>Destination file type</td></tr>
</tbody>
</table>
</div>
</details>

---

## Enums

<h3 id="enum-file-type" class="section-anchor">
  <span class="section-path">FILE_TYPE</span>
</h3>

<table class="fields-table">
<thead>
<tr><th>Value</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>UNKNOWN_FILE_TYPE</code></td><td>Unknown or unrecognized file type</td></tr>
<tr><td><code>REGULAR_FILE</code></td><td>Regular file</td></tr>
<tr><td><code>DIRECTORY</code></td><td>Directory</td></tr>
<tr><td><code>SYMLINK</code></td><td>Symbolic link</td></tr>
<tr><td><code>BLOCK_DEVICE</code></td><td>Block device</td></tr>
<tr><td><code>CHAR_DEVICE</code></td><td>Character device</td></tr>
<tr><td><code>SOCKET</code></td><td>Socket</td></tr>
<tr><td><code>FIFO</code></td><td>Named pipe (FIFO)</td></tr>
<tr><td><code>NO_FILE</code></td><td>No file (e.g. anonymous fd)</td></tr>
</tbody>
</table>

<h3 id="enum-connection-direction" class="section-anchor">
  <span class="section-path">CONNECTION_DIRECTION</span>
</h3>

<table class="fields-table">
<thead>
<tr><th>Value</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><code>INCOMING</code></td><td>Inbound connection</td></tr>
<tr><td><code>OUTGOING</code></td><td>Outbound connection</td></tr>
</tbody>
</table>

---

## Limitations

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_NEEDLE_LENGTH` | 32 | Maximum rule string length |
| `MAX_TOKENS_PER_RULE` | 128 | Maximum tokens in rule expression. Rules are converted to trees. token is equivalent to tree node (modifiable)|
| `MAX_RULES_PER_MAP` | 100 | Maximum rules per event type (modifiable)|


{: .important }
> **Case Sensitivity** — Everything in owLSM rules is case sensitive!

{: .note }
> **Other Sigma Keys** — Standard Sigma keys such as `title`, `logsource`, etc are allowed in owLSM rules but are ignored.