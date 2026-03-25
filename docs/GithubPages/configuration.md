---
layout: default
title: Configuration
nav_order: 3
permalink: /configuration/
---

# Configuration

owLSM has a single config file which controls every aspect of its behavior.  
See [How to generate a config](https://github.com/cybereason-labs/owLSM/blob/main/Rules/README.md) in the repo.

## Full Configuration Structure

<div class="interactive-code">
<pre><code>{
    "<a href="#features" class="code-link">features</a>": {
        "<a href="#features-file_monitoring" class="code-link">file_monitoring</a>": {
            "<a href="#features-file_monitoring-enabled" class="code-link">enabled</a>": true,
            "<a class="code-link">events</a>": {
                "<a href="#features-file_monitoring-events-chmod" class="code-link">chmod</a>": true,
                "<a href="#features-file_monitoring-events-chown" class="code-link">chown</a>": true,
                "<a href="#features-file_monitoring-events-file_create" class="code-link">file_create</a>": true,
                "<a href="#features-file_monitoring-events-unlink" class="code-link">unlink</a>": true,
                "<a href="#features-file_monitoring-events-rename" class="code-link">rename</a>": true,
                "<a href="#features-file_monitoring-events-write" class="code-link">write</a>": true,
                "<a href="#features-file_monitoring-events-read" class="code-link">read</a>": true,  # Due to high volume of read syscalls, we advise to disable.
                "<a href="#features-file_monitoring-events-mkdir" class="code-link">mkdir</a>": true,
                "<a href="#features-file_monitoring-events-rmdir" class="code-link">rmdir</a>": true
            }
        },
        "<a href="#features-shell_commands_monitoring" class="code-link">shell_commands_monitoring</a>": {
            "<a href="#features-shell_commands_monitoring-enabled" class="code-link">enabled</a>": true
        },
        "<a href="#features-network_monitoring" class="code-link">network_monitoring</a>": {
            "<a href="#features-network_monitoring-enabled" class="code-link">enabled</a>": true
        }
    },
    "<a href="#userspace" class="code-link">userspace</a>": {
        "<a href="#userspace-max_events_queue_size" class="code-link">max_events_queue_size</a>": 10000,
        "<a href="#userspace-output_type" class="code-link">output_type</a>": "JSON",
        "<a href="#userspace-log_level" class="code-link">log_level</a>": "LOG_LEVEL_INFO",
        "<a href="#userspace-set_limits" class="code-link">set_limits</a>": true
    },
    "<a href="#kernel" class="code-link">kernel</a>": {
        "<a href="#kernel-log_level" class="code-link">log_level</a>": "LOG_LEVEL_WARNING"
    },
    "<a href="{{ '/rules/' | relative_url }}" class="code-link">rules</a>": [ ... ]
}</code></pre>
</div>

---

## Configuration Reference

<h3 id="features" class="section-anchor">
  <span class="section-path">features</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> All monitoring features are enabled by default</p>
</div>
Control what security features are enabled.<br><br>
<strong>Features that are always enabled:<strong> exec monitoring, fork monitoring, and process exit monitoring.
</div>

<h3 id="features-file_monitoring" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> All filesystem monitoring features are enabled by default</p>
</div>

Controls file system monitoring. When enabled, owLSM hooks into file operations and can detect/prevent malicious file access.
</div>

<h3 id="features-file_monitoring-enabled" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>enabled</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Master switch for file system monitoring.
</div>

<h3 id="features-file_monitoring-events-chmod" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>chmod</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor chmod syscall
</div>

<h3 id="features-file_monitoring-events-chown" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>chown</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor chown syscall
</div>

<h3 id="features-file_monitoring-events-file_create" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>file_create</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor regular file creation
</div>

<h3 id="features-file_monitoring-events-unlink" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>unlink</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor unlink syscall (file deletion)
</div>

<h3 id="features-file_monitoring-events-mkdir" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>mkdir</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor mkdir syscall (directory creation)
</div>

<h3 id="features-file_monitoring-events-rmdir" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>rmdir</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor rmdir syscall (directory deletion)
</div>

<h3 id="features-file_monitoring-events-rename" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>rename</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor rename syscall
</div>

<h3 id="features-file_monitoring-events-write" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>write</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor write syscall. Only for regular files and symlinks.
</div>

<h3 id="features-file_monitoring-events-read" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>file_monitoring<span class="dot">.</span>events<span class="dot">.</span>read</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Monitor read syscall. Only for regular files and symlinks.<br>
Due to high volume of read syscalls, we strongly advise to disable this feature.
</div>

<h3 id="features-shell_commands_monitoring" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>shell_commands_monitoring</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>shell commands monitoring is enabled</code></p>
</div>

Monitor commands typed in interactive shell sessions (Bash, Zsh, Dash) and the commands to the process context. This allows you to write rules that match based on the shell command that initiated an operation.
</div>

<h3 id="features-shell_commands_monitoring-enabled" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>shell_commands_monitoring<span class="dot">.</span>enabled</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Enable shell command monitoring.<br>
Supported shells: Bash, Zsh, Dash.
</div>

<h3 id="features-network_monitoring" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>network_monitoring</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>network monitoring is enabled</code></p>
</div>

Controls network connection monitoring. <br>
Currently, only TCP connections are supported.
</div>

<h3 id="features-network_monitoring-enabled" class="section-anchor">
  <span class="section-path">features<span class="dot">.</span>network_monitoring<span class="dot">.</span>enabled</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Enable network connection monitoring.<br>
Currently, only TCP connections are supported.
</div>

---

<h3 id="userspace" class="section-anchor">
  <span class="section-path">userspace</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
</div>

The `userspace` section configures the userspace component of owLSM.
</div>

<h3 id="userspace-max_events_queue_size" class="section-anchor">
  <span class="section-path">userspace<span class="dot">.</span>max_events_queue_size</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>10000</code></p>
<p><strong>Options:</strong> Integer (1000 - 1000000)</p>
</div>

Maximum events in the processing queue.<br>
Controls the size of the event buffer. Larger values handle burst traffic better but use more memory.
</div>

<h3 id="userspace-output_type" class="section-anchor">
  <span class="section-path">userspace<span class="dot">.</span>output_type</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>"JSON"</code></p>
<p><strong>Options:</strong> <code>"JSON"</code></p>
</div>

Output format for events.<br>
"PROTOBUF" will be supported in the future. 
</div>

<h3 id="userspace-log_level" class="section-anchor">
  <span class="section-path">userspace<span class="dot">.</span>log_level</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>"LOG_LEVEL_INFO"</code></p>
<p><strong>Options:</strong> <code>"LOG_LEVEL_DEBUG"</code>, <code>"LOG_LEVEL_INFO"</code>, <code>"LOG_LEVEL_WARNING"</code>, <code>"LOG_LEVEL_ERROR"</code></p>
</div>

Logging verbosity for userspace.
</div>

<h3 id="userspace-set_limits" class="section-anchor">
  <span class="section-path">userspace<span class="dot">.</span>set_limits</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>true</code></p>
<p><strong>Options:</strong> <code>true</code>, <code>false</code></p>
</div>

Set climits. Should be enabled.
</div>

---

<h3 id="kernel" class="section-anchor">
  <span class="section-path">kernel</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>{ log_level: "LOG_LEVEL_WARNING" }</code></p>
<p><strong>Options:</strong> Object containing kernel configuration</p>
</div>

The `kernel` section configures the kernel component of owLSM.
</div>

<h3 id="kernel-log_level" class="section-anchor">
  <span class="section-path">kernel<span class="dot">.</span>log_level</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> <code>"LOG_LEVEL_WARNING"</code></p>
<p><strong>Options:</strong> <code>"LOG_LEVEL_DEBUG"</code>, <code>"LOG_LEVEL_INFO"</code>, <code>"LOG_LEVEL_WARNING"</code>, <code>"LOG_LEVEL_ERROR"</code></p>
</div>

Kernel-side logging verbosity. Keep at `LOG_LEVEL_WARNING` or higher in production for performance.
</div>

---

<h3 id="rules" class="section-anchor">
  <span class="section-path">rules</span>
</h3>

<div class="config-section">
<div class="field-meta">
<p><strong>Required:</strong> false</p>
<p><strong>Default value:</strong> No rules</p>
</div>

The `rules` array.<br>
See <a href="https://github.com/cybereason-labs/owLSM/blob/main/Rules/README.md" class="code-link">How to generate a config with rules</a> in the repo.
 
</div>
