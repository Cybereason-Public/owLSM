# Optimization target
**What:** Replaced the heap `std::string` members of `Path`, `CommandLine`, and `Filename` with inline buffers (`InlineString<PATH_MAX/CMD_MAX/FILENAME_MAX_LENGTH>`) so `Event` construction on the consume path would stop allocating a string per path and command line.
**Hypothesis:** `Event::Event` (~15%) / `Process::Process` (~10%) were a related set of heap string copies. Moving those strings inline should cut at least 8% of owLSM CPU. Events/s should stay the same or rise, drops stay 0, mean pressure-window machine CPU should stay the same or fall.

# Result
**What were the results:** Both post-runs agree, and they disagree with the hypothesis. `Event::Event` went up (14.57%/15.10% → 16.38%/16.44%). `event-consume` stayed ~63%. Path frames dropped (~3.3% → ~1.2%) and `basic_string` construction dropped (~3.8% → ~0.7%), but that was replaced by `InlineString` (~2.5%) plus a larger `Event` memcpy. Mean pressure CPU was flat (2.66%/2.62% → 2.61%/2.63%). Drops stayed 0. Events/s were 96497/96878 before and 96243/96852 after — no improvement, first post-run slightly lower. Not an 8% owLSM-CPU win.
**Did it fail any test:** Unit tests and Linux automation were not run; the change was rejected from the profiling numbers.
**Should we merge it in the code:** NO. Larger `Event` objects made construction more expensive; the string-alloc savings did not show up as lower owLSM CPU.
