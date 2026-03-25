---
layout: default
title: Events
nav_order: 5
permalink: /events/
---

# Events

owLSM produces two types of output: **Events** and **Errors**.<br>
**Events** - These are the normal output that informs us on whats happening on the system. The events are sent to STDOUT.<br>
**ERROR** - Error messages that report about errors and issues owLSM kernel component has faced. The errors are sent to STDERR.<br>
Most of the errors aren't critical and just inform us about thing like "failed to get cmd of pid 1778"

---

## Event Structure

Every event shares a common top-level structure. The `data` field varies depending on the event `type`.

```json
{
    "id": 42,
    "type": "FILE_CREATE",
    "action": "ALLOW_EVENT",
    "matched_rule_id": 0,
    "matched_rule_metadata": {
        "description": ""
    },
    "had_error": 0,
    "process": { },
    "parent_process": { },
    "time": 123456789012345,
    "data": { }
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Monotonically increasing event ID, global across all event types |
| `type` | string | Event type. See [Event Types](#event-types) |
| `action` | string | Action taken. See [Actions](#actions) |
| `matched_rule_id` | int | ID of the matched rule (0 if no rule matched) |
| `matched_rule_metadata` | object | Metadata from the matched rule (e.g. `description`) |
| `had_error` | int | Currently not supported |
| `process` | object | The process that triggered the event. See [Process Object](#process-object) |
| `parent_process` | object | The parent of the triggering process. See [Process Object](#process-object) |
| `time` | int | Nanoseconds since system boot (`bpf_ktime_get_ns`). This is a monotonic clock that starts at 0 when the system boots — it is **not** Unix epoch time. To convert to wall-clock time, add the difference between the current epoch time and the system uptime. |
| `data` | object | Event-specific data (varies by type). See [Event Data by Type](#event-data-by-type) |

---

### Event Types

| Type | Description |
|------|-------------|
| `EXEC` | Process execution |
| `FORK` | Process fork |
| `EXIT` | Process exit |
| `FILE_CREATE` | Regular file creation |
| `UNLINK` | File deletion |
| `MKDIR` | Directory creation |
| `RMDIR` | Directory deletion |
| `CHMOD` | Permission change |
| `CHOWN` | Ownership change |
| `WRITE` | File write |
| `READ` | File read |
| `RENAME` | File rename / move |
| `NETWORK` | Network connection (TCP) |

### Actions

| Action | Description |
|--------|-------------|
| `ALLOW_EVENT` | Do nothing. Event is sent normally |
| `BLOCK_EVENT` | Block the syscall/operation |
| `BLOCK_KILL_PROCESS` | Block the event and terminate the process |
| `BLOCK_KILL_PROCESS_KILL_PARENT` | Block the event and terminate the process and its parent |
| `KILL_PROCESS` | Don't block the event but terminate the process |
| `EXCLUDE_EVENT` | Don't send the event. Excluded events are not sent to userspace, so you will never recieve such event |

<h3 id="file-types">File Types</h3>

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

<h3 id="connection-directions">Connection Directions</h3>

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

<h3 id="process-object" class="section-anchor">Process Object</h3>

<details class="field-dropdown">
<summary><strong>Process Object</strong> — All process objects share this structure: process, parent_process, target.process, etc</summary>
<div class="field-content">

<div class="tab-container">
  <div class="tab-buttons">
    <button class="tab-button active" data-tab="process-example">Example JSON</button>
    <button class="tab-button" data-tab="process-schema">JSON Schema</button>
  </div>

  <div id="process-example" class="tab-content active">
    <div class="interactive-code">
<pre><code>{
    "pid": 1234,
    "ppid": 1000,
    "ruid": 0,
    "rgid": 0,
    "euid": 0,
    "egid": 0,
    "suid": 0,
    "cgroup_id": 5678,
    "start_time": 1707561200000000,
    "ptrace_flags": 0,
    "file": { <a href="#file-object" class="code-link"> File Object </a> },
    "cmd": "bash -c echo hello",
    "shell_command": "ls -la /etc",
    "stdio_file_descriptors_at_process_creation": {
        "stdin": "REGULAR_FILE",
        "stdout": "REGULAR_FILE",
        "stderr": "REGULAR_FILE"
    }
}</code></pre>
    </div>
  </div>

  <div id="process-schema" class="tab-content">
    <table class="fields-table">
    <thead>
    <tr><th>Field</th><th>Type</th><th>Description</th></tr>
    </thead>
    <tbody>
    <tr><td><code>pid</code></td><td>int</td><td>Process ID</td></tr>
    <tr><td><code>ppid</code></td><td>int</td><td>Parent process ID</td></tr>
    <tr><td><code>ruid</code></td><td>int</td><td>Real user ID</td></tr>
    <tr><td><code>rgid</code></td><td>int</td><td>Real group ID</td></tr>
    <tr><td><code>euid</code></td><td>int</td><td>Effective user ID</td></tr>
    <tr><td><code>egid</code></td><td>int</td><td>Effective group ID</td></tr>
    <tr><td><code>suid</code></td><td>int</td><td>SUID</td></tr>
    <tr><td><code>cgroup_id</code></td><td>int</td><td>Cgroup ID</td></tr>
    <tr><td><code>start_time</code></td><td>int</td><td>Process start time (nanoseconds since boot)</td></tr>
    <tr><td><code>ptrace_flags</code></td><td>int</td><td>Ptrace flags</td></tr>
    <tr><td><code>file</code></td><td>object</td><td>Process executable. See <a href="#file-object" class="code-link">File Object</a></td></tr>
    <tr><td><code>cmd</code></td><td>string</td><td>Command line arguments</td></tr>
    <tr><td><code>shell_command</code></td><td>string</td><td><strong>(Beta)</strong> Shell command typed in an interactive session. Populated only for monitored shells (Bash, Zsh, Dash). See <a href="/owLSM/architecture/shell-commands/">Shell Commands</a></td></tr>
    <tr><td><code>stdio_file_descriptors_at_process_creation</code></td><td>object</td><td>File types of stdin, stdout, stderr at process creation. Values are <a href="#file-types" class="code-link"><code>FILE_TYPE</code></a> enums</td></tr>
    </tbody>
    </table>
  </div>
</div>

</div>
</details>

<h3 id="file-object" class="section-anchor">File Object</h3>

<details class="field-dropdown">
<summary><strong>File Object</strong> — All file objects share this structure: target.file, process.file, etc.</summary>
<div class="field-content">

<div class="tab-container">
  <div class="tab-buttons">
    <button class="tab-button active" data-tab="file-example">Example JSON</button>
    <button class="tab-button" data-tab="file-schema">JSON Schema</button>
  </div>

  <div id="file-example" class="tab-content active">
    <div class="interactive-code">
<pre><code>{
    "inode": 654321,
    "dev": 2049,
    "path": "/usr/bin/bash",
    "owner": {
        "uid": 0,
        "gid": 0
    },
    "mode": 33261,
    "type": "REGULAR_FILE",
    "suid": 0,
    "sgid": 0,
    "last_modified_seconds": 1700000000,
    "nlink": 1,
    "filename": "bash"
}</code></pre>
    </div>
  </div>

  <div id="file-schema" class="tab-content">
    <table class="fields-table">
    <thead>
    <tr><th>Field</th><th>Type</th><th>Description</th></tr>
    </thead>
    <tbody>
    <tr><td><code>inode</code></td><td>int</td><td>Inode number</td></tr>
    <tr><td><code>dev</code></td><td>int</td><td>Device number</td></tr>
    <tr><td><code>path</code></td><td>string</td><td>Absolute file path</td></tr>
    <tr><td><code>owner.uid</code></td><td>int</td><td>File owner user ID</td></tr>
    <tr><td><code>owner.gid</code></td><td>int</td><td>File owner group ID</td></tr>
    <tr><td><code>mode</code></td><td>int</td><td>File permission mode</td></tr>
    <tr><td><code>type</code></td><td>enum <a href="#file-types" class="code-link"><code>FILE_TYPE</code></a></td><td>File type</td></tr>
    <tr><td><code>suid</code></td><td>int</td><td>SUID bit</td></tr>
    <tr><td><code>sgid</code></td><td>int</td><td>SGID bit</td></tr>
    <tr><td><code>last_modified_seconds</code></td><td>int</td><td>Last modification time in seconds (epoch)</td></tr>
    <tr><td><code>nlink</code></td><td>int</td><td>Hard link count</td></tr>
    <tr><td><code>filename</code></td><td>string</td><td>Filename (basename only)</td></tr>
    </tbody>
    </table>
  </div>
</div>

</div>
</details>

---

### Event Data by Type

<details class="field-dropdown">
<summary><strong>FILE_CREATE / UNLINK / MKDIR / RMDIR / READ / WRITE</strong> — Target file events</summary>
<div class="field-content">
<p>These events all share the same data structure — a single target file.<br>
For <code>MKDIR</code> and <code>RMDIR</code>, the file <code>type</code> will be <code>DIRECTORY</code>.</p>
<div class="interactive-code">
<pre><code>"data": {
    "target": {
        "file": { <a href="#file-object" class="code-link"> File Object </a> }
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>EXEC</strong> — Process execution event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "target": {
        "process": { <a href="#process-object" class="code-link"> Process Object </a> }
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>CHMOD</strong> — Permission change event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "target": {
        "file": { <a href="#file-object" class="code-link"> File Object </a> }
    },
    "chmod": {
        "requested_mode": 33261
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>CHOWN</strong> — Ownership change event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "target": {
        "file": { <a href="#file-object" class="code-link"> File Object </a> }
    },
    "chown": {
        "requested_owner_uid": 0,  // Due to an LSM bug, these are always 0
        "requested_owner_gid": 0   // Due to an LSM bug, these are always 0
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>RENAME</strong> — File rename / move event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "flags": 0,
    "rename": {
        "source_file": { <a href="#file-object" class="code-link"> File Object </a> },
        "destination_file": { <a href="#file-object" class="code-link"> File Object </a> }
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>NETWORK</strong> — Network connection event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "network": {
        "direction": "OUTGOING",
        "source_ip": "192.168.1.100",
        "destination_ip": "93.184.216.34",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": 6,
        "ip_type": 2
    }
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>EXIT</strong> — Process exit event</summary>
<div class="field-content">
<div class="interactive-code">
<pre><code>"data": {
    "exit_code": 0,
    "signal": 0
}</code></pre>
</div>
</div>
</details>

<details class="field-dropdown">
<summary><strong>FORK</strong> — Process fork event</summary>
<div class="field-content">
<p>Fork events have no additional data fields. The <code>data</code> field is an empty object <code>{}</code>.</p>
</div>
</details>

---

## Error Structure

```json
{
    "details": "bpf_probe_read_user failed. pid: 1837369",
    "error_code": -1,
    "location": "get_cmd_from_task:34"
}
```

### Error Fields

| Field | Type | Description |
|-------|------|-------------|
| `details` | string | the message that is logged in owLSM kernel componenet |
| `error_code` | int | code. mostly -1 |
| `location` | string | `function name`:`line number` |
