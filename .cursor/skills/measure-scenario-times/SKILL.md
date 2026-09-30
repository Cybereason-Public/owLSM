---
name: measure-scenario-times
description: Adds temporary pytest-bdd timing hooks and writes debug_scenario_times.txt plus sorted step and scenario files. Use when the user asks to measure scenario time, step time, or why K8s or Linux automation tests are slow.
---

# Measure scenario times

The user names the suite: **K8s** (`src/Tests/K8S_Automation`) or **Linux** (`src/Tests/Automation`). Add the hooks only in that suite. Remove them when the user says measuring is done.

## Hooks

In that suite's `conftest.py`, write `~/owLSM/debug_scenario_times.txt`. One line per event. Overwrite the file at session start (`write_text`). Append every later line. Skip all of this when `collectonly` is set.

Clock: `datetime.now().strftime("%H-%M-%S")` → `[HH-MM-SS]`. Elapsed seconds, one decimal: `(datetime.now() - start).total_seconds()`.

Store `scenario_start_time` and `step_start_time` on the suite global:

- K8s: `globals/global_objects.py` (`global_objects`)
- Linux: `globals/system_related_globals.py` (`system_globals`)

| Hook | When to write | Line |
|---|---|---|
| `pytest_sessionstart` | first line, before existing setup | `[HH-MM-SS] session start` |
| `pytest_bdd_before_scenario` | first line, then set `scenario_start_time`, then existing work | `[HH-MM-SS] before scenario: '{scenario.name}'` |
| `pytest_bdd_before_step` | first line, then set `step_start_time` | `[HH-MM-SS] before step: '{step.name}'` |
| `pytest_bdd_after_step` | last line | `[HH-MM-SS] {seconds} after step: '{step.name}'` |
| `pytest_bdd_after_scenario` | last line, after existing cleanup | `[HH-MM-SS] {seconds} after scenario: '{scenario.name}'` |
| `pytest_sessionfinish` | last line, after existing cleanup | `[HH-MM-SS] session end` |

`{seconds}` uses `step_start_time` or `scenario_start_time`. Quote names with single quotes. Writing before the existing before-scenario work keeps the gap before the first step in the log.

## Sorted files

After the run, write these next to the log. Sort by the seconds field, largest first. Keep the original lines.

- `~/owLSM/sorted_step_time.txt` — lines containing ` after step: `
- `~/owLSM/sorted_scenario_time.txt` — lines containing ` after scenario: `

## Run the suite

- **Kind:** `src/Tests/K8S_Automation/AGENTS.md`. `conftest.py` creates and deletes the cluster.
- **OKE:** from the repo root, `kubernetes/oke/run_oke.sh`. Extra args are passed to pytest. Set `OWLSM_IMAGE_REPOSITORY` and `OWLSM_IMAGE_TAG`. `OWLSM_OKE_SKIP_NODE_POOL_RECYCLE=1` skips node-pool recycle when the pool is already fresh.
- **Linux:** `src/Tests/Automation/README.md`. Run pytest as root from that directory.

Do not commit the timing hooks or the three txt files.
