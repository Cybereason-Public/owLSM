---
layout: default
title: Architecture
nav_order: 6
has_children: true
permalink: /architecture/
---

# Architecture

Here we discuss and describe how different components of owLSM work.

## Deep Dives

| Component | Description |
|-----------|-------------|
| [Rule Creation and Evaluation](rule-evaluation/) | Full flow of rules. From YAML to in kernel evaluation |
| [Process Cache](process-cache/) | Process cache managment. Flow and best practices |
| [Event Flow](event-flow/) | How events flow from kernel hooks to userspace output |
| [Event Caching](event-caching/) | high-frequency events are caching |
| [Shell Command Monitoring](shell-commands/) | How interactive shell commands are captured using uprobes |
| [Agentic Profiling Loop](agentic-profiling-loop/) | How the C++ CPU optimization agentic loop is built |
