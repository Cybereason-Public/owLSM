Open sourcing our Linux security agent! 
What is the project: owLSM is an eBPF LSM agent that implements a stateful Sigma Rules Engine.
owLSM focuses on three main things:
1) Prevention capabilities using a Sigma Rules Engine implemented via eBPF LSM.
2) Data correlation between eBPF probes for stateful prevention capabilities.
3) Security-focused system monitoring where each event contains all the context a security expert needs.

Why we created this project: After years of personal use of tools like Tetragon, KubeArmor and Falco I kept running into the same issues. These solutions offer little to no prevention (enforcement) capabilities. Those that do offer enforcement policies lack basic features like substring matching or even a full-process-command-line attribute.

How we solve it: We decided to take a completely different approach
1) Use the standard Sigma Rules structure and support as many Sigma Rules features as possible (constantly adding more).
2) Solve the core limitation of current eBPF LSM projects: they are stateless. Almost all data available in an enforcement rule comes only from the current hook.
We created stateful eBPF programs that use multiple consecutive hook points and correlate data between them, so at the point of the prevention decision, users have all the data they need. We took this stateful approach to the extreme. 

Who is it for: Teams and companies that protect Linux and Cloud environments. Developers and agents looking for implementation examples of complex eBPF solutions.

We at @cybereason decided to open source this project as we aspire to become the gold standard for prevention and detection for Linux.
We want the community to test it, give us feedback and hopefully contribute. 


# in first comment
https://github.com/Cybereason-Public/owLSM
And while you are there, give us a star {star emoji}