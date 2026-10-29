# Optimization target
**What:** `flushLocalQueue` copied every `event_t` from the local vector into `std::deque<event_t>`. That deque copy was about 18% of owLSM samples (`_M_push_back_aux` 17.54% / 18.47%, libc memcpy under it 12.85% / 13.63%). The change moves each full local batch (`std::vector<event_t>`) onto a deque of batches and recycles up to two spare buffers, so a full flush no longer copies each raw event.
**Hypothesis:** Removing that second copy should cut about 12–17% of owLSM CPU, above the 8% bar. Events/s should stay within 2%, drops should stay 0, and mean pressure-window machine CPU should fall.

# Result
**What were the results:** Both post-runs agree, and they miss the hypothesis. The deque copy is gone (`flushLocalQueue` 19.13% / 20.12% → 1.75% / 1.76%). The remaining vector copy in `eventReceivedCallback` got about twice as expensive (10.57% / 9.96% → 21.56% / 21.60%; absolute samples ~4.9B / 5.3B → ~9.6B / 9.2B), so most of the saved work came back. Mean pressure CPU fell only from 2.641% / 2.665% to 2.457% / 2.445% (about 7.0% and 7.4% below the lower baseline). Drops stayed 0. Events/s were 96749 / 96420 before and 96133 / 96835 after; the lower post value is 0.3% under the lower pre value. RSS rose from about 79 MB to about 88 MB.
**Did it fail any test:** Unit tests and Linux automation were not run; the change was rejected from the profiling numbers.
**Should we merge it in the code:** NO. The second `event_t` copy disappeared, but owLSM CPU fell by less than 8%.
