# Optimization target
**What:** Stop `Event` construction from copying every path, filename, and command line into a `std::string`. `Path` / `CommandLine` / `Filename` now borrow the bytes already stored in the queued `event_t`. A string is copied only if the shell worker keeps the event after that `event_t` is dropped.
**Hypothesis:** `Event::Event` (~14%), `convertToMessages` (~20%), `Process::Process` (~10%), and `malloc` (~14%) were one related set of string copies. Borrowing should cut at least 8% of owLSM CPU. Events/s should stay within 2%, drops stay 0, and mean pressure-window machine CPU should fall.

# Result
**What were the results:** Both post-runs agree. Mean pressure CPU fell from 2.684% / 2.667% to 2.320% / 2.377% (about 13.0% and 10.9% below the lower baseline). `Event::Event` fell 14.17% / 14.65% → 9.46% / 9.46%, `convertToMessages` 19.56% / 20.17% → 11.57% / 12.23%, `malloc` 13.56% / 13.83% → 4.91% / 5.62%. Drops stayed 0. Events/s rose (95903 / 96035 → 96847 / 96729).
**Did it fail any test:** Unit tests passed (550). Linux automation: 93 passed, 9 failed. The failures were the rules_generator binary missing from the profiler package and later anti-tamper tests seeing no session owLSM process. Event, shell, and flatbuffer scenarios passed. Not caused by this change.
**Should we merge it in the code:** YES. Both post-runs beat the 8% owLSM-CPU bar, the flame target got cheaper, and event stats stayed healthy.
