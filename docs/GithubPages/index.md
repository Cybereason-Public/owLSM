---
layout: default
title: Home
nav_order: 1
permalink: /
---

<div class="landing-hero">
  <img src="{{ '/assets/images/owLSM_logo-Photoroom.png' | relative_url }}" alt="owLSM Logo" class="landing-logo">
  
  <p class="landing-tagline">
    <i>🛡️ owLSM aspires to become the gold standard for prevention and detection on Linux systems 🛡️</i>
  </p>
</div>

owLSM is an eBPF LSM agent that implements a stateful Sigma rules engine focused on prevention.

<p>
<b><span style="font-size:1.15em">What is the project:</span></b> owLSM focuses on three main things:<br>
1) Prevention capabilities using a Sigma Rules Engine implemented via eBPF LSM.<br>
2) Data correlation between eBPF probes for stateful prevention capabilities.<br>
3) Security-focused system monitoring where each event contains all the context a security expert needs.
</p>

<p>
<b><span style="font-size:1.15em">Who is it for:</span></b> Teams that defend Linux systems, companies offering Linux/Cloud security solutions, and developers or agents looking for implementation examples of complex eBPF solutions.
</p>

<p>
<b><span style="font-size:1.15em">Where is it already being used:</span></b> Customers of the security firms Cybereason and LevelBlue.
</p>

<p>
<b><span style="font-size:1.15em">Why we created this project:</span></b> After years of using projects like Falco, Tetragon, and KubeArmor, we kept running into the same gaps. These solutions offer little to no prevention (enforcement) capabilities. Those that do offer enforcement policies lack basic features like substring matching, regex matching, full process cmd matching, and parent termination of malicious processes.<br>
We decided to take a completely different approach:<br>
1) Use the standard Sigma rules structure and support as many Sigma rules features as possible (constantly adding more).<br>
2) Solve the core limitation of current eBPF LSM projects: they are stateless. Almost all data available in an enforcement rule comes only from the current hook.<br>
We created stateful eBPF programs that use multiple consecutive hook points and correlate data between them, so at the point of the prevention decision, users have all the data they need. We took this stateful approach so far that, for example, when monitoring write events, you can specify prevention rules based on the shell command that initiated the write.
</p><br>


<div class="landing-buttons">
  <a href="https://github.com/cybereason-labs/owLSM" class="landing-button landing-button-primary" target="_blank">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
    View on GitHub
  </a>
  <a href="https://discord.gg/gQk5Jxd6vs" class="landing-button landing-button-secondary" target="_blank">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
    Join Discord
  </a>
</div>

---

Help us grow and protect the world by giving us a ⭐ on [GitHub](https://github.com/cybereason-labs/owLSM)!
