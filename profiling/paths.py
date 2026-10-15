from pathlib import Path


PROFILING_DIR = Path(__file__).resolve().parent
REPO_ROOT = PROFILING_DIR.parent
WORK_DIR = PROFILING_DIR / "work"
FINISH_FILE = WORK_DIR / "finish"
RESULTS_DIR = PROFILING_DIR / "results"
DEFAULT_OWLSM_BIN = REPO_ROOT / "build" / "owlsm" / "bin" / "owlsm"

CONFIGS_DIR = PROFILING_DIR / "configs"

WORKER_COUNT = 4
SHELL_LOOP = PROFILING_DIR / "shell_loop.sh"
WORKLOAD_SCRIPT = PROFILING_DIR / "workload.py"
SIGNAL_SENDER_SCRIPT = PROFILING_DIR / "signal_sender.py"
