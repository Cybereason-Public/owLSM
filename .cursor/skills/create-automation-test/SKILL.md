---
name: create-automation-test
description: >-
  Writes, runs, and validates owLSM pytest-bdd automation tests for Linux (src/Tests/Automation) and Kubernetes (src/Tests/K8S_Automation). 
  Use when creating, adding, or fixing an automation test (scenario), or when checking that a new automation test passed for the correct reason.
---

# Create automation test

## Full loop

This skill is for creating a new automation test or tests.
It will write the test, run it and validate that it passed for the correct reason.

Here is the full loop:
1. Write the test - using the `Automation Test writing` section.
2. run only that test. How to run a single test is specified in both `src/Tests/Automation/README.md` & `src/Tests/K8S_Automation/README.md`. Choose the appropriate one based on the platform.
3. If the test failed, investigate it, and fix it.
    - If the reason of the failure is a bug in the product you are testing, either fix it or report it. Depends on the context.
        + If you fixed it yourself, go back to step 2.
        + If someone else needs to fix it (user or different agent), stop here as you depend on them to fix it.
    - If the reason of the failure is in the test itself, go back to step 1 and fix the test.
4. Validate the test - Once the test passes, validate it using the Automation Test validation section.
5. Run all the tests
    - If the user didn't ask you to also run all the tests together after creating the new test, stop here.
    - If the user asks to run all the tests, run them all. just see they all passed, and no reason to validate them again.
        + If something fails:
            * investigate it.
            * if its related to the new test, investigate further and try to fix it (fix it as described in step 3)
            * A later test that fails can be leftover machine or owlsm state from the new test. Treat that failure as related until the logs show it is not.
        + If everything passes, stop here.

So the loop only stops if:
1) Everything passes.
2) The agent needs another entity (user or different agent) to fix something.

## Automation Test writing

This section is for writing automation tests, both Linux `src/Tests/Automation` and K8S `src/Tests/K8S_Automation`.
Follow it when writing the test.

### Understand what to test
Make sure that you understand the core functionality we are testing. If you don't, ask the user for clarification.
The owLSM source code is the one we are testing, so you can't just read it and assume you understand the feature, as the code may be doing the wrong thing.

### Make sure that we test the correct things
Sometimes the feature we are testing has a bug, thus the test fails.
In those situations we must not modify the test around the bug, thus making it pass. The bug must be fixed.
So if this agent catches a bug in the tested feature, using a test, the bug must be fixed.
Depending on the agent that uses this skill, and its context, the bug may be fixed by:
- This current agent.
- Another agent, then this agent must report the bug to the other agent.
- The user, then this agent must report the bug to the user.

### re-use existing steps
We use bdd testing framework. We should always try and re-use existing steps, rather than create new ones.
See if the new test can be fully created using existing steps. If not, create the new steps.
Search before adding a step: Linux `src/Tests/Automation/common_steps/`, K8S `src/Tests/K8S_Automation/steps/`.
Bind the scenario in that suite's `features/all_test.py`.

Event checks search every JSON line in `owLSM_output.log`. Every field in the table must match. Name the fields that can only be this action (path, command, pid, mode). A table with only `type` can match a different event in the same scenario. Use a placeholder only for a value the scenario does not know yet, such as a pod uid and pid.
`I dont find the event` passes whenever nothing matches, including when the action never ran. Pair it with proof the action ran. `read_event_disabled_in_config` finds the WRITE and then requires the READ to be absent. `chmod event stops after helm disables chmod` sees chmod on one path while enabled, then requires chmod on a different path to be absent while disabled.

### Use existing infrastructure
When you need to create a new step, try and implement that step using the existing infrastructure. If you can't, create the new infra.
When creating the new infra, see if it can easily be done by a simple extension of the existing infra. If yes, thats always the best option. If not, create the new infra.

### Kubernetes main node
All work on a K8s test happens only on `main_node` unless the scenario says otherwise. That includes creating pods, searching events, searching logs or anything else. Almost every scenario only needs that node.

### Start and end states of the test
Tests should start and end in the same state.
This means that the machine state and the owlsm state should be the same at the start and end of the test.
This will make the machine clean for each test, which makes the tests more reliable and easier to debug when they fail.

When I say "machine" I mean the machine that pytest is running on. So on k8s tests, we don't need to ensure this for the remote nodes and pods.

#### Start state
- We should assume that at the start of each test, owlsm is running, unless the test specifies otherwise.
- The first 1-2 steps should always refer to the owlsm state. Either they ensure that its running, or not running.

#### End of the test
The tests need to always clean after itself and leave the machine and owlsm in the same state it found it in.
- In Linux tests, the machine state should be managed by the state_db's. Thus when doing things like running a process, creating a file, etc', we should always use the existing utils functions as they add the new "object" to the state_db.
- In K8S tests, the cluster state should be managed by the stated_db's. But not things like processes and files, as they run on the pods and nodes and not on the machine that runs the pytest itself.
- owlsm state management is very important, and unless specified otherwise, owlsm should be restored to the state it was in at the start of the test. This means if we changed a config in the test, we need to restore it to the original state at the end of the test. See for example:
    + Linux test: `read_event_disabled_in_config` we restart owlsm at the end, with the default config.
    + K8S test: `chmod event stops after helm disables chmod` we enable chmod again at the end.
- You must never assume that this test or a new test is the last test in the suite. As new tests will be added. So don't leave anything dirty because you reasoned it was the last test.

##### Exceptions - When not to clean.
The tests have order, so we know what test comes after the other.
If Test A changes something in owlsm/machine and test B needs the same state as Test A, then there is no reason to clean after Test A.
For example, if test A changes the owlsm config, and test B needs the same config, then test A shouldn't reset the config at the end of the scenario.
However, if test C, doesn't need the same config as Test A, then Test B should reset the config state at the end, as the next test, C, needs a different config.

### Speed - tests should be fast
This doesn't "override" the other points, but try to design the tests in a way that they are fast.
- Single test point of view: When writing a test think about how to make it fast.
- Multiple test point of view: When we have a new feature that requires multiple new tests, try to think how to design them and their execution order in a way that is fast. Why order matters: `##### Exceptions - When not to clean.`

## Automation Test validation

When creating a new test, and it passes we need to validate that it passed for the correct reason.
Automation tests are complex and may have bugs or design issues, that will cause them to pass for the wrong reason.
This section is for validating that the test passed for the correct reason.

### Logs
There are few important logs, that should be checked when validating a test.

owLSM related logs:
- automation.log
- owlsm.log
- owLSM_output.log

See `Log Files` section in `src/Tests/K8S_Automation/AGENTS.md` & `src/Tests/Automation/AGENTS.md` for more info about what the logs represent.

System logs:
- `cat /sys/kernel/debug/tracing/trace`: will be useful only on Linux tests. It has the ebpf code "stdout". When has a lot of content, older content is removed.

Analyze these logs to see if the test passed for the correct reason.
You don't need to use all of them always, depends on the test.

### Verdict
First understand what the test is trying to check. What component and what its intended functionality.
Then decide if the intended behavior of both the feature and the test itself are correct based on the logs.
A green pytest result is not that decision. `I find the event` passes when any line in `owLSM_output.log` matches the table. `I dont find the event` passes when no line matches.

1. Write the claim in one sentence: which action must show up, and which action must not.
2. In `automation.log`, take each `Found event in output` line for this scenario. That JSON is the event the step accepted. Check the fields the table did not list. If the line is a different action from this scenario, the test passed for the wrong reason.
3. For each `I dont find the event` step, show the action ran. A sibling event, a file-size or command step, or the same action succeeding before the feature was turned off. If you cannot show that, the absence is not evidence.
4. If the scenario changed config or helm values, confirm `owlsm.log` or `automation.log` shows owlsm reloaded, and confirm the scenario restored the previous values before it ended.
5. Read `/sys/kernel/debug/tracing/trace` only for a Linux test whose question is whether the eBPF hook ran. Read it immediately. Older lines are dropped.

Report one verdict: correct pass, false pass (what matched instead), or product bug (the test is right and the behavior is wrong). If you spot an issue, report it. Do not change the test to match a product bug.
