# CrackArmor mitigation with owLSM
A few weeks ago Qualys released a writeup about vulnerabilities they found in AppArmor, A Linux kernel security module that provides Mandatory Access Control.
Since then I saw many people talk about it, as its really a master class of vulnerabilities. 
After LowLevelTV released a video talking about CrackArmor, I decided this is a great opretunity to show how owLSM can prevent many types of vulnerabilites. 
This blog will show how easy it is to write rules for new malicious behaviors (Malwares, Vulnerabilities, etc') and preventing them with owLSM.

## CrackArmor in a nutshell
CrackArmor groups 9 vulnerabilities, where the most intresting one allows an unprivileged local attacker to load, replace, and remove arbitrary AppArmor profiles. 
Using it Qualys were able to do: LPE, DoS and bypass Access Control Restrictions. 
Full report: https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt 

## First step, monitoring CrackArmor 
In order to understand what rule to create for CrackArmor, we must see what events owLSM generates when we exploit the vulnerability.
1. We run owLSM without any config, so its in "observability only" mode: `root@vm:/opt/owLSM$ ./owlsm > events.log`
2. We exploit the vulnerability
```bash
bob@vm:/tmp$ id
uid=1004(bob) gid=1004(bob) groups=1004(bob),100(users)
bob@vm:/tmp$ ls -l /sys/kernel/security/apparmor/policy/profiles/*rsyslogd*
total 0
-r--r--r-- 1 root root 0 Nov 26 16:31 attach
-r--r--r-- 1 root root 0 Nov 26 16:31 learning_count
-r--r--r-- 1 root root 0 Nov 26 16:31 mode
-r--r--r-- 1 root root 0 Nov 26 16:31 name
lr--r--r-- 1 root root 0 Nov 26 16:31 raw_abi -> ../../raw_data/0/abi
lr--r--r-- 1 root root 0 Nov 26 16:31 raw_data -> ../../raw_data/0/raw_data
lr--r--r-- 1 root root 0 Nov 26 16:31 raw_sha256 -> ../../raw_data/0/sha256
-r--r--r-- 1 root root 0 Nov 26 16:31 sha256
bob@vm:/tmp$ su -P -c 'stty raw && echo -n rsyslogd' "$USER" > /sys/kernel/security/apparmor/.remove
Password: # The unprivileged user password
bob@vm:/tmp$ ls -l /sys/kernel/security/apparmor/policy/profiles/*rsyslogd*
ls: cannot access '/sys/kernel/security/apparmor/policy/profiles/*rsyslogd*': No such file or directory
```
We can see that an unprivileged user is able to remove apparmor profiles using the vulnerability.

3. Now we go through the events owLSM generated, looking for intresting CrackArmor related events.
We see the following event
```json
{
  "action": "ALLOW_EVENT",
  "id": 11644,
  "matched_rule_id": 0,
  "matched_rule_metadata": {
    "description": ""
  },
  "time": 10519555087103153,
  "type": "WRITE",
  "data": {
    "target": {
      "file": {
        "dev": 6,
        "filename": ".remove",
        "inode": 2151,
        "last_modified_seconds": 1774694243,
        "mode": 438,
        "nlink": 1,
        "owner": {
          "gid": 0,
          "uid": 0
        },
        "path": "/sys/kernel/security/apparmor/.remove",
        "sgid": 0,
        "suid": 0,
        "type": "REGULAR_FILE"
      }
    }
  },
  "parent_process": {
    "cgroup_id": 1925910,
    "cmd": "bash",
    "egid": 1004,
    "euid": 1004,
    "file": {
      "dev": 264241152,
      "filename": "bash",
      "inode": 5112276,
      "last_modified_seconds": 1711874463,
      "mode": 493,
      "nlink": 1,
      "owner": {
        "gid": 0,
        "uid": 0
      },
      "path": "/usr/bin/bash",
      "sgid": 0,
      "suid": 0,
      "type": "REGULAR_FILE"
    },
    "pid": 2072312,
    "ppid": 2072310,
    "ptrace_flags": 0,
    "rgid": 1004,
    "ruid": 1004,
    "shell_command": "su -P -c 'stty raw && echo -n rsyslogd' \"$USER\" > /sys/kernel/security/apparmor/.remove",
    "start_time": 10519274821794975,
    "stdio_file_descriptors_at_process_creation": {
      "stderr": "CHAR_DEVICE",
      "stdin": "CHAR_DEVICE",
      "stdout": "CHAR_DEVICE"
    },
    "suid": 1004
  },
  "process": {
    "cgroup_id": 1925910,
    "cmd": "su -P -c stty raw && echo -n rsyslogd bob",
    "egid": 1004,
    "euid": 0,
    "file": {
      "dev": 264241152,
      "filename": "su",
      "inode": 5122498,
      "last_modified_seconds": 1712671357,
      "mode": 493,
      "nlink": 1,
      "owner": {
        "gid": 0,
        "uid": 0
      },
      "path": "/usr/bin/su",
      "sgid": 0,
      "suid": 1,
      "type": "REGULAR_FILE"
    },
    "pid": 2073929,
    "ppid": 2072312,
    "ptrace_flags": 0,
    "rgid": 1004,
    "ruid": 1004,
    "shell_command": "",
    "start_time": 10519552320407529,
    "stdio_file_descriptors_at_process_creation": {
      "stderr": "CHAR_DEVICE",
      "stdin": "CHAR_DEVICE",
      "stdout": "REGULAR_FILE"
    },
    "suid": 0
  }
}
```

Understanding the Event
owLSM events are very descriptive and contain a lot of information. To understand each attribute see [Events Breakdown](https://cybereason-public.github.io/owLSM/events/)
Looking at the event we can see the following:
- The event type is `WRITE`
- The target file is `/sys/kernel/security/apparmor/.remove`
- parent_process.shell_command shows us the command that was executed
- The process that initiated the write operation is `su`
- The process is running with a SUID bit set `process.file.suid: 1` which is required for the vulnerability.
- The process euid (effective user id) is 0 (root) but the ruid (real user id) is 1004 (bob). This is due to the suid. 




## Writing the rule 

We need to try to write 1 agnostic rule that will cover all cases of this vulnerability.
If you read Qualys report you know that:
CrackArmor vulnerabilities target different files in `/sys/kernel/security/apparmor/`
Attacker can use any SUID binary that will allow them to control what is written to the `/sys/kernel/security/apparmor/*` files. Not only `su`.

```YAML
title: CrackArmor mitigation
id: 1
description: "CrackArmor: block non-root writes using suid binaries to AppArmor control files"
logsource:
    product: linux
    category: file_event

action: "BLOCK_KILL_PROCESS"
events:
    - WRITE
detection:
    selection_apparmor_path:
        target.file.path|startswith: "/sys/kernel/security/apparmor"
    selection_suid_binary:
        process.file.suid: 1
    filter_root:
        process.ruid: 0
    condition: selection_apparmor_path and selection_suid_binary and not filter_root
```

**What the rule does:**
Monitors write events
To paths starting with `/sys/kernel/security/apparmor` 
Where the binary that is used to write is a SUID binary
And the real user ID isn't 0 (so its not actualy root doing the writing)
When this happens, owLSM will block the write operation and kill the process. 