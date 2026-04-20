I want to create a post with a table that compares between tetragon and owLSM.
In tetragon im speaking about the latest official release version https://github.com/cilium/tetragon/tree/v1.6.1

so im going to list here important things that:
- owLSM has and tetragon doesn't
- tetragon has and owLSM doesn't

# Important points

## Prevention/Enforcment vs Monitoring/Obesrvability 
1. Prevention/Enforcment means preventing an operation from happening. for example stopping a syscall using LSM.
From now on I will use only the word prevention.

2. Monitoring/Obesrvability means auditing the system and generating events on what is running on the system. Then if you spot that a malicious activity occured, you can act and remmidiate it.
From now on I will use only the word monitoring.

3. Tetragon has enforcment policies, while owLSM has sigma rules. I will refer to both as enforcment_rules from now on.

4. Tetragon is the better solution for monitoring.
It offers more event types, and allows you to better "select" what you want to monitor on your system.

5. owLSM is a better solution for prevention.
owLSM enforcment_rules offer more features and data that can be used to match an event against. 

---

# owLSM has and tetragon doesn't

## Prevention capabilities comparison
In this comparison I want to focus on the enforcment_rules and the prevention capabilities, not on the monitoring capabilities. 
So what can users do with enforcment_rules.


### enforcment_rules substring matching
owLSM offers substring matching in its enforcment_rules while tetragon doesn't.

### enforcment_rules regex matching
owLSM offers regex matching in its enforcment_rules while tetragon doesn't.

### enforcment_rules fieldref matchig
owLSM offers fieldref matching in its enforcment_rules while tetragon doesn't.
Using this you can compare 2 fields of an event. This is a "dynamic" comparison as the event data isn't specified in advanced its of the event itself.

### enforcment_rules conditions
This lets us create complex conditions to when the event matches or doesn't match the enforcment_rule. 
You do this with `and`, `or`, `not`, `parenthesis`, etc'
This allows the user to create very complex conditions for when the rule matches, and allows him to "merge" multiple rules into one.

### enforcment_rules uses a standard rules language
Sigma rules is the most standard and widely used security rules language in the world.
This doesn't requires users to learn a new language and makes it easier to import rules.
For example users can go to SigmaHQ and import linux rules in an almost plug and play way (only minor adaptation is needed).

Tetragon created a new "rules language" (CRD) that requieres knowledge in the linux kerenel and learning the CRD language
On top of that its importing rules from 3rd party resources like SigmaHQ is nearly impossible.

This is why supporting the sigma language was so important to us, as we knew it would make our users life easier and give them stringer tools. 

### enforcment_rules don't require deep understanding in the linux kernel.
Tetragon enforcment_rules require users to have knowledge of the kernel (and the specific kernel version they are using). As they need to specify the hooked function name, its arguments, and "manually" walk kernel structures. 
owLSM comletley abstracts the kernel, and you just need basic high level knowledge of what you want to defend against. 

### enforcment_rules matching against full process CMD
Tetragon doesn't offer you the full process CMD as a single string. 
You can manually access its comm object or specific arguments, but your enforcment_rules can't match against the full process CMD.
owLSM does @src/Kernel/struct_extractors.bpf.h:15-56  in order to get the full process CMD as a single string and let you match against it. 

### enforcment_rules refer to original parent process
in Linux when your parent process exits, you become a child of a new process (pid 1 almost always)
When specifying the parent process in enforcment_rules, you are always intrested in the original parent, even if he has exited already.
Tetragon is stateless, thus enforcment_rules always refer to the current parent, even if the original parent exited and now your parent is pid 1. So rules specifying parent process aren't reliable. 
owLSM eBPF program is stateful. Thus it tracks the original parent of each process and even if the original parent exited, when specifying processing enforcment_rules that specify the parent, owLSM uses the original parent and not pid 1.

This is important as a lot of Linux malware spawn a malicious child process and kill the parent. So inline security tools will be "blind" to the real parent process.

### enforcment_rules ability to kill parent process
Malicious processes/shell-sessions will execute binaries like chmod/curl/etc for their operations. This means that rules that match against the event and kill the process, actually kill the child proces which is chmod/curl/etc instead of killing the parent process, as chmod/curl are the ones that actually did the malicious operations. This isn't good as the malicious processes/shell-sessions is never remidiated.
Thats why owLSM gives users the option to block the event, kill the process and kill the parent process all together. 
While tetragon can only block the event and block the process itself, but can't kill the parent process.

owLSM does this safe, as it will only try to kill the parent process if its the original parent, and if its not pid 1.


### enforcment_rules based on the shell command that was executed
eBPF allows you to hook userspace processes using `uprobes`
This is how tetragon allows its users to monitor bash commands as they can hook `bash:readline`. 
However, `uprobes` can't block the activity, so tetragon doesn't offer a way to prevent malicious behavior based on the shell command. 
owLSM is a stateful eBPF app so it corrolates data from `uprobes` and from in kernel LSM hooks, and allows users to levrage the LSM hooks to block activity of malicious shell commands it previously recorded via `uprobes`

On top of that, `bash:readline` is a simple example of a uprobe hook that is used to monitor shell commands. But this won't work with `dash` for example. 
This is where tetragon lack capability to even monitor shell commands, while owLSM allows you not only to monitor but prevent as well. 

See more: https://cybereason-public.github.io/owLSM/architecture/shell-commands.html


### enforcment_rules using statefull hooks
Tetragon allows you to specify what function you want to hook and the data you can get is only data available in that hook (arguments, current task, etc)
many times this isn't enough as the current hook lacks a lot of data. 
owLSM abstracts the hook from the user, and actually "links" many hooks and corrolates data between the hooks, so the user will have a statefull enforcment_rules expirience. 
For example the on_exec.bpf.c uses 3 LSM hooks to get all the needed data about the exec (old process, new process, parent process)
or the on_tcp_incomming.bpf.c that reuqiers us to corrolate data between 2 different hooks in order to have the full connection picture (src ip, dst ip, src port, dst port, etc') at the prevention desicion moment. 


## Capabilities not related to prevention
These are other features/capbilities that owLSM has that tetragon donesn't. However these aren't related to prevention.

### FlatBuffers support
Both owLSM and Tetragon use IPC or other I/O techniqe to send the events. 
Both can generate huge amount of output. 
Both can send the output as json. 
Tetragon supports output as protobuff as well.
owLSM supports output as flatbuffers as well.
FlatBuffer is order of magnatude more efficient for the reader side for these products usecase. 



# tetragon has and owLSM doesn't

## Prevention capabilities comparison
In this comparison I want to focus on the enforcment_rules and the prevention capabilities, not on the monitoring capabilities. 
So what can users do with enforcment_rules.

### prevention hooking points 
while owLSM offers prevention on a small set of hooking points
Tetragon offers prevention on every hooking point that the kernel exports
These are all the LSM hooks and the kprobes that support bpf_override_return


## Supported platforms
Which platforms does Tetragon support and owLSM doesn't

### K8S
Tetragon fully supports monitoring and prevention on k8s.
owLSM currently only supports Linux machines.

### Linux Kernel version
Tetragon most basic version suports Kernel 4.19 and above
owLSM supports Kernel 5.14