#!/usr/bin/env python3
"""Take the loop lock, or exit if another skill run already holds it."""

import os
import shutil
import sys
from pathlib import Path


def repo_root():
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "Makefile").is_file() and (candidate / "profiling" / "README.md").is_file():
            return candidate
    raise SystemExit("[preflight] error: could not find the owLSM repo root")


def lock_dir(root):
    return root / "profiling" / "loop.lock"


def pid_is_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_lock_pid(lock):
    pid_file = lock / "pid"
    if not pid_file.is_file():
        return None
    text = pid_file.read_text(encoding="utf-8").strip()
    if not text.isdigit():
        return None
    return int(text)


def main():
    lock = lock_dir(repo_root())
    if lock.exists():
        holder = read_lock_pid(lock)
        if holder is not None and pid_is_alive(holder):
            raise SystemExit(f"[preflight] error: lock held by pid {holder} ({lock})")
        shutil.rmtree(lock)
    try:
        lock.mkdir()
    except FileExistsError:
        raise SystemExit(f"[preflight] error: lock already exists ({lock})")
    try:
        (lock / "pid").write_text(f"{os.getpid()}\n", encoding="utf-8")
    except Exception:
        shutil.rmtree(lock, ignore_errors=True)
        raise
    print(f"[preflight] lock {lock}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        sys.exit(f"[preflight] error: {error}")
