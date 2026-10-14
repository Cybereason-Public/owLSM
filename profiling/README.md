# profiling

Linux x86_64 userspace profiling for owLSM. Build with `make profiler` (production build plus `-g` and `PROFILER_BUILD`). Record after the log line `Attached all probes`.

# tracked metrics

- Flame graph per thread. CPU time by function
- Resources graph. Every 1 second, written to an HTML file you open in the browser: RSS and virtual memory in MB, and CPU % of the machine. Not per thread. 
- Heap profiling. `heaptrack` across the session. Compare different heap snapshots at different times.
- Event drop rate. Drops in the kernel ring buffer, the userspace queue (`max_events_queue_size`), and the stdout write. 
- Events per second. How many events owlsm generates in a second.
- Lock contention. 


# How to run a profiling session

Build the profiler binary, then run one test as root. The run writes SVGs or an HTML file under `profiling/results/`.

```bash
make profiler -j$(nproc)
sudo python3 profiling/start.py --list
sudo python3 profiling/start.py Flame_Graph_Idle
sudo python3 profiling/start.py Flame_Graph_pressure_no_matches
sudo python3 profiling/start.py Flame_Graph_pressure_yes_matches
sudo python3 profiling/start.py resources_graph
```

`Flame_Graph_*` writes `overall.svg` and one SVG per thread.   
`resources_graph` writes `resources_graph.html` with plotly. Open either in a browser.

The profiling machine needs `perf`, `flamegraph.pl`, and `stackcollapse-perf.pl` for the flame graphs, and `python3-plotly` for the resources graph. See `scripts/oci_testing_machines_setup/ubuntu_24_profiling.sh`.

# How to setup the profiling machine

- Choose the owlsm ubuntu 24 image.
- Shape: VM.Standard.E5.Flex, 8 OCPUs, 1 Gbps network bandwidth, 16 GB memory, block storage only.
