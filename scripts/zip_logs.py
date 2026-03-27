#!/usr/bin/env python3
"""Collects automation, runner, and machine logs into a zip archive for CI debugging."""

import argparse
import logging
import os
import shutil
import socket
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path

COLLECT_DIR = Path("/tmp/all_logs")
DEFAULT_AUTOMATION_DIR = "/opt/owLSM/src/Tests/Automation"
RUNNER_DIAG_DIR = Path("/home/ghrunner/actions-runner/_diag")
COMMAND_TIMEOUT_SEC = 60


def setup_logging() -> logging.Logger:
    COLLECT_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("zip_logs")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(COLLECT_DIR / "zip_logs.log")
    fh.setFormatter(fmt)
    log.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    log.addHandler(ch)

    return log


def copy_file(src: Path, dest_subdir: str, log: logging.Logger):
    if not src.exists():
        log.warning(f"File not found: {src}")
        return
    dest = COLLECT_DIR / dest_subdir
    dest.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(src, dest / src.name)
        log.info(f"Copied {src} -> {dest / src.name}")
    except Exception as e:
        log.error(f"Failed to copy {src}: {e}")


def copy_dir(src: Path, dest_subdir: str, log: logging.Logger):
    if not src.is_dir():
        log.warning(f"Directory not found: {src}")
        return
    dest = COLLECT_DIR / dest_subdir
    try:
        shutil.copytree(src, dest, dirs_exist_ok=True)
        log.info(f"Copied directory {src} -> {dest}")
    except Exception as e:
        log.error(f"Failed to copy directory {src}: {e}")


def run_command(cmd: str, output_name: str, dest_subdir: str, log: logging.Logger):
    dest = COLLECT_DIR / dest_subdir
    dest.mkdir(parents=True, exist_ok=True)
    out_file = dest / output_name
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SEC
        )
        out_file.write_text(result.stdout)
        if result.returncode != 0:
            log.warning(f"Command exited with {result.returncode}: {cmd}")
            if result.stderr:
                log.warning(f"  stderr: {result.stderr[:500]}")
        else:
            log.info(f"Collected: {cmd} -> {out_file}")
    except subprocess.TimeoutExpired:
        log.error(f"Command timed out ({COMMAND_TIMEOUT_SEC}s): {cmd}")
    except Exception as e:
        log.error(f"Failed to run: {cmd}: {e}")


def create_zip(output_dir: Path, log: logging.Logger) -> Path:
    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    zip_path = output_dir / f"{hostname}_{timestamp}.zip"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(COLLECT_DIR):
                for f in files:
                    full = Path(root) / f
                    zf.write(full, full.relative_to(COLLECT_DIR))
        size_mb = zip_path.stat().st_size / (1024 * 1024)
        log.info(f"Created zip: {zip_path} ({size_mb:.1f} MB)")
    except Exception as e:
        log.error(f"Failed to create zip: {e}")

    return zip_path


def main():
    parser = argparse.ArgumentParser(description="Collect and zip CI logs")
    parser.add_argument("--automation-dir", default=DEFAULT_AUTOMATION_DIR)
    parser.add_argument("--output-dir", default="/tmp/collected_logs")
    args = parser.parse_args()

    auto = Path(args.automation_dir)

    if COLLECT_DIR.exists():
        shutil.rmtree(COLLECT_DIR)

    log = setup_logging()
    log.info("=== Starting log collection ===")

    # --- Automation logs ---
    copy_dir(Path("/tmp/automation_logs"), "automation", log)

    # --- Runner logs ---
    copy_dir(RUNNER_DIAG_DIR, "runner/_diag", log)
    run_command(
        "journalctl -u 'actions.runner.*' --no-pager",
        "runner_journal.log", "runner", log,
    )

    # --- Machine logs ---
    for path in ["/var/log/cloud-init.log", "/var/log/cloud-init-output.log", "/var/log/auth.log"]:
        copy_file(Path(path), "machine", log)
    run_command("journalctl --no-pager -b", "system_journal.log", "machine", log)
    run_command("cat /sys/kernel/debug/tracing/trace", "trace.log", "machine", log)

    zip_path = create_zip(Path(args.output_dir), log)
    log.info("=== Log collection complete ===")
    print(zip_path)


if __name__ == "__main__":
    main()
