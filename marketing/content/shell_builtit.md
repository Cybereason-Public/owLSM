# Shell Built-in Commands: A Hacker's Undetectable Weapon

I've spent 5 years working on Linux security projects. Hackers are still beating us with shell built-in commands. **But that ends today!**

This is a technical deep-dive into why monitoring and preventing malicious shell built-ins is so damn hard, and how we finally solved it.

> Not familiar with shell built-in commands?   
> It's a simple concept, ask GPT for a 5-line explanation.

Let's talk about `echo` and how overpowered it is. Attackers love these:
```bash
# Add SSH keys 
echo "ssh-rsa AAA..." >> ~/.ssh/authorized_keys

# Create a user
echo "redteam:x:1002:1002::/home/redteam:/bin/bash" >> /etc/passwd
```

Key points:
1. **What's a "malicious" command?** A command that *actually does* malicious things, not just *looks* malicious. Avoid false positives.
2. **Prevention, not just detection.** This isn't 2018. We aren't interested only in detecting malicious behavior. We need to stop the operation *before* it executes. Not during, and definitely not after.
3. **useradd and other CLI tools.** Attackers try to avoid dedicated CLI tools like useradd. These tools are closely monitored, making malicious usage easy to detect and block.
4. **/etc/passwd is just an example** from now on we are going to focus on `echo XYZ >> /etc/passwd`. But this is just a single example for the usage of shell built-in commands. Attackers use it for many different things as well.

# How Do We Monitor and Prevent This?

## Approaches I Tried (and Failed)

**1) Shell config files** (bashrc, zshrc, /etc/profile, etc')

Using these files we can set hooks that run monitoring software before each command

Problems:
- Some shells don't have config files (for example: dash — the default shell on Ubuntu/Debian/Mint)
- Easily bypassed: `bash --norc --noprofile`

**2) Replace shell binaries with custom ones**

Problems:
- Attackers can bring their own shell
- Not production-stable
- user updates shell

**3) eBPF uprobes - Bash readline**

Good direction, but far from perfect:
- readline is an easy target to hook. What do you target in zsh? Or In other shells?
- Dash doesn't export symbols — how do you hook it?
- How do you know when a command finishes and the next one starts?
- uprobes don't offer prevention capabilities.
- Detecting "malicious" commands based on string comparison only, creates false positives.
  For example:
  + Malicious: `echo "ssh-rsa AAA..." >> ~/.ssh/authorized_keys`
  + False positive: `echo ' "ssh-rsa AAA..." >> ~/.ssh/authorized_keys '` (just prints the string)
  
  We need to observe *behavior* and only then compare strings.

## Security Tools Are Blind Too

Unfortunately, security tools are blind to shell built-in commands as well.  
Let's test the two best Linux security tools: **Tetragon** and **Sysdig** (Falco).   These are the two best security tools for Linux, with over 10K github stars combined.

**Scenario**: prevent malicious writes to `/etc/passwd` via shell built-ins.

### Sysdig

Sysdig is an excellent observability tool, arguably the best. It lacks prevention capabilities, but for the sake of this example lets say it does have.   
We are going to monitor **incoming write** events for the `/etc/passwd` file and see what data sysdig provides.    
I run sysdig and ask for all the relevant data:
```bash
sudo sysdig -v -p '
EVENT: time=%evt.datetime type=%evt.type dir=%evt.dir category=%evt.category
  args: %evt.args

PROCESS: name=%proc.name pid=%proc.pid 
  exe: %proc.exepath
  cmdline: %proc.cmdline
  cwd: %proc.cwd

PARENT: name=%proc.pname ppid=%proc.ppid
  exe: %proc.pexepath
  cmdline: %proc.pcmdline

FILE: fd=%fd.num name=%fd.name type=%fd.type dir=%fd.directory file=%fd.filename
' 'fd.name=/etc/passwd and evt.type=write and evt.dir=">"'
```

Then in another terminal I ran
```bash
root@ubuntu-24-04:/tmp$ echo "redteam:x:1002:1002:RedTeam User:/home/redteam:/bin/bash" >> /etc/passwd
```

And we recived the following event
```bash
EVENT: time=2026-03-11 15:21:59.265882923 type=write dir=> category=file
  args: fd=1(<f>/etc/passwd) size=57 

PROCESS: name=bash pid=793517 
  exe: /usr/bin/bash
  cmdline: bash
  cwd: /tmp/

PARENT: name=bash ppid=792891
  exe: /usr/bin/bash
  cmdline: bash

FILE: fd=1 name=/etc/passwd type=file dir=/etc file=passwd
```

Sysdig correctly shows that `bash` wrote to `/etc/passwd`. But that's only part of the story.

### Tetragon

Now the king of prevention. Tetragon is strong in both observability and prevention.

Tetragon *can* monitor `bash::readline`, but its rules are stateless, you can't correlate the readline hook with the LSM write hook.

Here's a tetragon config monitoring writes to `/etc/passwd`:
```yaml
metadata:
  name: "passwd-write-monitor"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
      - index: 1
        operator: "Mask"
        values:
        - "2"  # MAY_WRITE = 2
```

Same result: we see a write to /etc/passwd happened, but not the full picture.

```bash
# sudo tetra getevents -o json | jq 'select(.process_kprobe != null)'
{
  "process_kprobe": {
    "process": {
      "exec_id": "dWJ1bnR1LTI0LTA0OjE5OTY3NDA0ODAwMDAwMDA6NzkzNTE3",
      "pid": 793517,
      "uid": 0,
      "cwd": "/tmp",
      "binary": "/usr/bin/bash",
      "flags": "procFS",
      "start_time": "2026-03-11T15:13:56.907462920Z",
      "auid": 1001,
      "parent_exec_id": "dWJ1bnR1LTI0LTA0OjE5OTY2NTA2NjAwMDAwMDA6NzkyODkx",
      "refcnt": 1,
      "tid": 793517,
      "in_init_tree": false
    },
    "parent": {
      "exec_id": "dWJ1bnR1LTI0LTA0OjE5OTY2NTA2NjAwMDAwMDA6NzkyODkx",
      "pid": 792891,
      "uid": 0,
      "cwd": "/home/admin",
      "binary": "/usr/bin/bash",
      "flags": "procFS",
      "start_time": "2026-03-11T15:12:27.087462949Z",
      "auid": 1001,
      "parent_exec_id": "dWJ1bnR1LTI0LTA0OjE5OTY2NTA2NTAwMDAwMDA6NzkyODkw",
      "tid": 792891,
      "in_init_tree": false
    },
    "function_name": "security_file_permission",
    "args": [
      {
        "file_arg": {
          "path": "/etc/passwd",
          "permission": "-rw-r--r--"
        }
      },
      {
        "int_arg": 2
      }
    ],
    "action": "KPROBE_ACTION_POST",
    "policy_name": "passwd-write-monitor",
    "return_action": "KPROBE_ACTION_POST"
  },
  "node_name": "ubuntu-24-04",
  "time": "2026-03-11T15:29:47.398880652Z"
}

```


### The Problem

Even the best tools don't show us the full picture.
We don't see what is written, what was the command, append or overwrites, etc'. 

For observability, we could get all the data post-execution with Tetragon and Sysdig. But for **prevention**, we need everything *before* the operation.

## Don't Lose Hope

I've shown you why defending against malicious shell built-ins is hard. Every approach has gaps.  
But now let's talk about how to actually do it right.

# Enter owLSM

owLSM is a new open-source project aiming to become the gold standard for Linux detection and prevention. It's a Sigma rules engine implemented with eBPF LSM, covering the security gaps other solutions leave open.

### How owLSM Solves This

**1) Stateful rules engine**

Unlike Tetragon and Sysdig's stateless approach, owLSM chains multiple eBPF hooks and correlates them using caches (ebpf maps). This creates a stateful engine that gives you all the data you need *at the point of prevention*.

The flow:
```
shell_uprobes (capture full command) → LSM hooks (make prevention decision based on command + event data) → shell_uprobes (indicate when command finished)
```

**2) Smart uprobes hooking methods**  

Currently owLSM supports 3 shells: bash, zsh and dash (We encourage the community to add support for more shells).

We said uprobes are problematic. Here's how owLSM handles it:
- owLSM team did an indepth research on each shell. What are the correct hooking points of each shell, How can we get the full command, how can we determine a command has finished, etc'.
- First, try hooking via exported symbols
- If symbols unavailable, use `libdebuginfod` to fetch symbols
- If that fails, no pressure. owLSM maintains an offline data base of all the official builds of the supported shells. The db has a `{binary build Id}-{offsets-to-hook}` table, so it will extract the buildId of the shell, and get the offsets to hook from the DB.

**3) The craziest eBPF code you'll see**

To extract commands from dash, owLSM walks userspace memory trees and reconstructs them as strings in eBPF. Check it out: [**dash_shell_command.bpf.c**](https://github.com/Cybereason-Public/owLSM/blob/main/src/Kernel/Programs/shell_command_monitoring/dash/dash_shell_command.bpf.c)

### owLSM stateful rule
Due to the stateful approach owLSM takes, our users are able to write such a sigma rule and prevent the malicious write:
```
... sigma rules stuff ...

description: "Example rule - Block manually added user"
action: "BLOCK_EVENT"
events:
    - WRITE
detection:
    selection_shell_command:
        process.shell_command|contains|all: 
            - ">> /etc/shadow"
            - "echo"
    selection_target:
        target.file.path: "/etc/shadow"
    condition: selection_shell_command and selection_target
```

---

**Want to go deeper on how owLSM handles shell commands?** Read the full architecture: [Shell Commands Monitoring Documentation](https://cybereason-public.github.io/owLSM/architecture/shell-commands.html)

**The full implementation is open-source:**  [owLSM](https://github.com/Cybereason-Public/owLSM)
