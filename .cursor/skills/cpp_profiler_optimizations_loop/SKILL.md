---
name: cpp-profiler-optimizations-loop
description: >-
  Profiles owLSM userspace, attempts one optimization, remeasures, and keeps the change if the post-optimization results show an improvement. 
  Writes a KB report and opens a PR when the change is worth keeping. 
  Use when asked to run cpp_profiler_optimizations_loop, optimize owLSM from profiling results, or /loop this skill with its expected arguments.
disable-model-invocation: true
---

# C++ profiler optimizations loop

This skill runs one optimization attempt. It profiles owLSM, picks a single CPU improvement, implements it, profiles again, and then either keeps the change (report + optional PR) or throws it away (report is optional).

It can be started by the user or by `/loop`. Either way, follow this file from top to bottom. Do not skip steps.

Run commands from the repo root unless a step says otherwise.

- How to run profiling tests: `profiling/README.md`
- How to build and run unit tests: `src/Tests/unit_test/AGENTS.md`
- How to run Linux automation: `src/Tests/Automation/README.md`

## Arguments

The skill takes one optional argument: the scenario.

| Scenario | Tests to run |
|---|---|
| `CPU_JSON` | `FlameGraphPressureNoMatches`, `ResourceGraph`, `EventStatistics` |
| `CPU_FLATBUFFER` | `FlameGraphPressureNoMatchesFlatbuffers`, `ResourceGraphFlatbuffers`, `EventStatisticsFlatbuffers` |

Run the tests one after another on this machine. Run **each** test **twice** before the optimization (baseline) and **twice** after it.

If the argument is missing, default to `CPU_JSON`. If it is anything other than the two names above, stop and tell the user. Do not start preflight.

## Scripts

These live next to this skill. Run them. Do not rewrite them.

```bash
python3 .cursor/skills/cpp_profiler_optimizations_loop/scripts/preflight.py
python3 .cursor/skills/cpp_profiler_optimizations_loop/scripts/revert.py              # restore src/Userspace and drop the lock
python3 .cursor/skills/cpp_profiler_optimizations_loop/scripts/revert.py --lock-only  # drop the lock, keep src/Userspace
.cursor/skills/cpp_profiler_optimizations_loop/scripts/clean_and_rebuild_owlsm_for_profiling.sh
```

- `preflight.py` takes a lock so two runs of this skill cannot overlap. If it fails, stop.
- The rebuild script wipes the old profiler build, builds owlsm for profiling, and copies it to `profiling/owlsm`. If it fails, stop. Exception: after you have already changed code (step 8), a failed rebuild is your bug — fix it and run the script again.
- `revert.py` puts `src/Userspace` back and drops the lock. Use `--lock-only` when you want to keep the Userspace changes.

## Flow

Work through these steps in order.

1. Read the scenario argument (see Arguments). If it is invalid, stop.
2. Run `preflight.py`. If it fails, stop.
3. Run `clean_and_rebuild_owlsm_for_profiling.sh`. If it fails, run `revert.py --lock-only` and stop.
4. Run each test in the scenario, twice, one run after the other. How to run a test is in `profiling/README.md`. If a test fails, stop.
5. Confirm results exist under `profiling/results/<TestName>/<DDMMYYYY_HHMMSS>/`. Each test should have two timestamped directories. These are the baseline. Read `overall.svg`, `resources_graph.html`, and `event_statistics.json` result files in both directories. See **How to analyze the profiling results**.
6. Choose a single optimization candidate. See **Choosing an optimization candidate**. This is the only change you will try in this run. If you cannot find a good candidate, run `revert.py`, tell the user why, and stop.
7. Implement that one optimization. You may edit only `src/Userspace/**`.
8. Run `clean_and_rebuild_owlsm_for_profiling.sh` again. The first rebuild already worked, so a failure here is from your change. Investigate, fix, and run the script again. This step is finished only when the rebuild succeeds.
9. Run each scenario test twice again (two post-optimization runs).
10. Compare all four result sets per test: baseline 1, baseline 2, post 1, post 2. Read `overall.svg`, `resources_graph.html`, and `event_statistics.json` result files in all four. See **How to analyze the profiling results**.
11. Decide keep or reject from the numbers. The rules are in **Keep or reject**. On reject: write the report (step 15), then go to step 16.
12. Build and run the unit tests (`src/Tests/unit_test/AGENTS.md`). If they fail, see **When unit tests fail**. That section will either let you continue (after updating a test) or send you to reject (step 15, then 16).
13. Run only the Linux automation scenarios (`src/Tests/Automation`) tagged `profiler_safe`. As specified in `src/Tests/Automation/README.md`. But add `-m profiler_safe` to the command to run only the tagged `profiler_safe` scenarios ` PYTHONPATH=$AUTOMATION_ROOT_DIR pytest features/ -v -s -m profiler_safe`.
Never edit those tests. If no tests are collected, stop and tell the user the tag is missing. If a failure is caused by your change, reject (step 15, then 16).
14. Clean up the optimization diff. The git commit and PR may contain **only** the edits the optimization itself needs, plus any unit-test updates from step 12. No markdown files, profiling results, lock files, or anything else.
15. Write the KB report and diff on disk. See **Report and KB**.
16. Finish:
    - **Not interested** (no candidate, weak/disagreed results, or a test failure you will not keep): tell the user the full report path and a 3-line summary, run `revert.py`, and stop.
    - **Interested, but `gh` is missing or not logged in**: tell the user the full report path and a 3–5 line summary, run `revert.py --lock-only`, and stop.
    - **Interested and `gh` is ready**: create a branch from `main` named after the KB folder **without** the date. Commit, push, and open a PR into `main`. The PR body is the report. Then run `revert.py` and summarize for the user in 3–5 lines.
    - If `gh` or git publish fails: run `revert.py --lock-only` and stop with the error.

## How to analyze the profiling results

There are three kinds of result files. A scenario uses all three tests, so you will see all three kinds.

**Flame graph (`overall.svg`)** — one graph with every owLSM thread. Use it to find functions or stack traces that run often or are expensive. Frame titles look like `function (N samples, X.XX%)`. After a change, the function or stack you targeted should take less CPU than before.

**Resource graph (`resources_graph.html`)** — CPU, RSS, and virtual memory over time, sampled once a second from `/proc`. CPU is percent of the whole machine (all cores), not one thread. The graph marks when pressure started and ended. The CPU number to compare is the **average** CPU % of the machine **under pressure** (between those two markers). Do not use the idle windows. Use this graph to see whether owLSM actually used less CPU / RSS / virtual memory.

**Event statistics (`event_statistics.json`)**:

| Field | Meaning |
|---|---|
| `ring_buffer_alloc_failures` | Kernel ring-buffer allocation failures |
| `queue_full_drops` | Events dropped because `m_main_queue` was full |
| `successful_events_written` | Events successfully written to stdout |
| `failed_events_written` | Events that failed to write to stdout |
| `events_per_second` | Successful writes divided by the measured seconds |

These numbers tell you how many events owLSM produced end-to-end and how many it lost. They matter as much as CPU.

### Keep or reject

Each test is run twice before the change and twice after. Read `overall.svg`, `resources_graph.html`, and `event_statistics.json` from all four runs (whichever of those files that test produces).

Look at all three signals together: did mean pressure CPU/RSS/virt go down, did event statistics stay healthy, and did the function you targeted take less CPU — without hurting overall resource use.

Keep only if **all** of these are true:

- **Both** post-optimization runs show similar **CPU improvement** versus the baseline: the flame target got cheaper, and mean pressure CPU went.
- That CPU improvement meets the bar in **Choosing an optimization candidate**, in both post-optimization runs.
- None of the reject rules below are hit.

Events/s does not have to go up. It is only a safety check.

Reject if **any** of these are true:

- The CPU gain of one of the post-runs is below the bar in **Choosing an optimization candidate**.
- Any event drop number goes up in any post-run.
- Average CPU % of the machine under pressure goes up in any post-run.
- Events/s fails the check below.

Events per second: do **not** reject because one post-run is a few events/s below one pre-run. Compare it like this:

1. Take the **lower** of the two pre-optimization `events_per_second` values.
2. Take the **lower** of the two post-optimization `events_per_second` values.
3. Reject only if the lower post value is more than **2%** below the lower pre value. Otherwise events/s is fine.

The 2% margin is there because the number of syscalls on the machine is not fully under the test's control. Even two runs of the same binary differ.

## Choosing an optimization candidate

CPU only. Do not attempt memory optimizations or locking optimizations. There is no flow for those yet.

1. Read both baseline `overall.svg` files. Find functions or stack traces that are hot (called a lot, or expensive each time).
2. Pick **one** function, or one related set that a single change will move together. Examples: the same helper used on several threads, something that owns a shared resource, or different stacks of the same thread. We only want work that can cut at least **8%** of owLSM's CPU, so the target itself must be at least 8%, or the related set must be. If you cannot find that, treat it as "no candidate" (flow step 6).
3. Write a hypothesis **before** you edit code. It should say:
    - which function or stack you will change
    - how you will change it (the actual idea)
    - the CPU % you think you can save
    Do not list metrics you expect to stay the same. End with: the rest of the metrics are supposed to stay the same.
4. Now read `kb/index.md`. You already have a target, so you know what to look for: a previous attempt on this function or stack, with a similar idea. 
If you find one, read that attempt's `report.md` and see what it tried and why it failed. If it is the same approach, go back to step 2 and pick a different target. If every remaining target was already tried the same way, run `revert.py`, tell the user, and stop.

You do not need to read every old report up front. `index.md` is a short list. Open a report only when its summary matches the candidate you just chose.

## When unit tests fail

Investigate the failure before you decide anything. Do not "fix" a failed test by weakening it unless the case below says you may.

Ask: did this optimization change **owLSM's runtime behavior** (what it does for the system: events, rules, what users see), or only an **internal detail** that does not change that behavior?

- **Runtime behavior changed.** We do not want this optimization. Reject it (flow step 15, then 16).
- **Only an internal detail changed**, and you **agree** with that internal change. Update the unit test to match the new internal detail, then continue to automation.
- **Only an internal detail changed**, but you **do not agree** with that change. Reject it.

Never edit the automation tests. If automation fails because of your change, reject.

## Report and KB

The KB is this skill's memory across runs. Later agents use it so they do not retry the same idea. Humans read it too.

Path: `.cursor/skills/cpp_profiler_optimizations_loop/kb/`

Always start with `kb/index.md`. That is the only file that must exist. Everything else is one folder per attempt:

```
kb/
├── index.md
├── error-consume-cv-instead-of-sleep-25102026/
│   ├── report.md
│   └── diff.md
├── async-shell-in-memory-cache-of-known-shells-26102026/
│   ├── report.md
│   └── diff.md
```

Folder name: `{slug}-{DDMMYYYY}`. `slug` is 1–10 hyphenated words that describe the attempt.

After every attempt, add a bullet at the top of `index.md`, example:
```
- [error-consume-cv-instead-of-sleep-25102026](error-consume-cv-instead-of-sleep-25102026) — 1–4 line summary of the report.
```

`report.md`:

```markdown
# Optimization target

**What:**
1–5 sentences on what you tried to optimize.

**Hypothesis:**
Why this was a good candidate, and the CPU you expected to save.

# Result

**What were the results:**
Numbers vs what you expected.
Did both post-optimization runs show the same improvement?

**Did it fail any test:**
Unit tests or automation. 1 line.

**Should we merge it in the code:**
YES/NO and why. 1 line.
```
