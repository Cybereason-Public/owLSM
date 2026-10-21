from pathlib import Path


class Strings:
    LOG_PREFIX = "[profiling]"
    PROFILING_DIR = Path(__file__).resolve().parent
    OWLSM_BIN = PROFILING_DIR / "owlsm" / "bin" / "owlsm"
    OWLSM_LOG = OWLSM_BIN.parent / "owlsm.log"
    CONFIG_DIR = PROFILING_DIR / "resources" / "config"
    RULES_NO_MATCH_DIR = PROFILING_DIR / "resources" / "rules" / "no_match"
    RESULTS_DIR = PROFILING_DIR / "results"
    KILLER_SCRIPT = PROFILING_DIR / "owlsm_killer.py"
    WORKLOAD_SCRIPT = PROFILING_DIR / "workload.py"
    FINISH_FILE = Path("/tmp/finish")
    OWLSM_PID_FILE = Path("/tmp/owlsm_profiling.pid")
    WORK_ROOT = Path("/tmp/profiling_work")
    ATTACHED_LINE = "Attached all probes"
    CONFIG_NO_RULE_MATCHES = "no_rule_matches_config.json"
    CONFIG_YES_RULE_MATCHES = "config_yes_rule_match.json"
    OWLSM_EVENTS_LOG = "owlsm_events.jsonl"
    MATCHED_RULE_FIELD = '"matched_rule_id":111'  # must match generate_configs.py's YES_MATCH_RULE_ID
    OVERALL_SVG = "overall.svg"
    STACKS_FOLDED = "stacks.folded"
    PERF_DATA = "perf.data"
    RESOURCE_GRAPH_HTML = "resources_graph.html"
    PRESSURE_START_LABEL = "pressure start"
    PRESSURE_END_LABEL = "pressure end"
    PROFILER_STATS_LABEL = "Profiler stats: "  # must match the LOG_INFO prefix in profiler_stats.hpp (PROFILER_BUILD)
    EVENT_STATISTICS_JSON = "event_statistics.json"
    RENAME_A = "rename1"
    RENAME_B = "rename2"
    FILES_DIR = "files"
    DIRS_DIR = "dirs"
    GROUP_ROOT = "root"
    GROUP_OTHER = "nogroup"
    SHELL = "/bin/sh"
    SHELL_SIGNAL = "kill -s USR1 {pid}"
    VETH_HOST = "p{index}h"
    VETH_NAMESPACE = "p{index}n"
    NAMESPACE = "prof{index}"
    HOST_IP = "10.210.{index}.1"
    NAMESPACE_IP = "10.210.{index}.2"
    PRESSURE_SUBNET = "10.210.0.0/16"
    PERF = "perf"
    STACKCOLLAPSE = "stackcollapse-perf.pl"
    FLAMEGRAPH = "flamegraph.pl"
    IP = "ip"
    IPTABLES = "iptables"


class Numbers:
    ATTACH_TIMEOUT_SECONDS = 60
    ATTACH_POLL_SECONDS = 1
    KILLER_POLL_SECONDS = 0.1
    KILLER_GRACE_SECONDS = 30
    KILLER_CHECK_SECONDS = 1
    OWLSM_STOP_TIMEOUT_SECONDS = 45
    PRESSURE_LOOP_SECONDS = 120
    IDLE_PROFILE_SECONDS = 120
    WORKER_CPU_MULTIPLIER = 1.5
    POOL_SIZE = 200
    NEXT_NAME = 201
    CONNECT_TIMEOUT_SECONDS = 1
    SHELL_TIMEOUT_SECONDS = 2
    LISTENER_READY_SECONDS = 5
    BASE_PORT = 19100
    PERF_STOP_TIMEOUT_SECONDS = 120
    FILE_MODE_A = 0o640
    FILE_MODE_B = 0o660
    LOG_TAIL_LINES = 40
    RESOURCE_GRAPH_IDLE_SECONDS = 30
    RESOURCE_SAMPLE_INTERVAL_SECONDS = 1.0
    RESOURCE_SAMPLER_STOP_TIMEOUT_SECONDS = 5


def log(message):
    print(f"{Strings.LOG_PREFIX} {message}", flush=True)
