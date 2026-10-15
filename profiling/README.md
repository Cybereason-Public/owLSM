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

Run one test at a time. The run writes SVGs or an HTML file under `profiling/results/`.

```bash
# Run as root, from the root directory
# start the docker
docker pull ghcr.io/cybereason-public/owlsm-ci:latest
docker run -it --rm -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash

# Build the profiler binary
make profiler -j$(nproc)

# exit docker
exit

# create a venv and install the requirements
cd profiling
uv venv venv
source venv/bin/activate
uv pip install -r requirements.txt

python start.py --list
python start.py Flame_Graph_Idle
python start.py Flame_Graph_pressure_no_matches
python start.py Flame_Graph_pressure_yes_matches
python start.py resources_graph
```

`Flame_Graph_*` writes `overall.svg` and one SVG per thread.   
`resources_graph` writes `resources_graph.html` with plotly. Open either in a browser.

The profiling machine needs `perf`, `flamegraph.pl`, and `stackcollapse-perf.pl` for the flame graphs. See `scripts/oci_testing_machines_setup/ubuntu_24_profiling.sh`.

# How to setup the profiling machine

- Choose the owlsm ubuntu 24 image.
- Shape: VM.Standard.E5.Flex, 8 OCPUs, 1 Gbps network bandwidth, 16 GB memory, block storage only.
