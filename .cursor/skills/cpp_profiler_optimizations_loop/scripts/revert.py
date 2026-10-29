#!/usr/bin/env python3
"""Restore src/Userspace and release the loop lock."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def repo_root():
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "Makefile").is_file() and (candidate / "profiling" / "README.md").is_file():
            return candidate
    raise SystemExit("[revert] error: could not find the owLSM repo root")


def git(root, args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def restore_userspace(root):
    restore = git(root, ["restore", "--worktree", "--staged", "--", "src/Userspace"])
    if restore.returncode != 0:
        raise SystemExit(f"[revert] error: git restore src/Userspace failed:\n{restore.stderr}")
    clean = git(root, ["clean", "-fd", "--", "src/Userspace"])
    if clean.returncode != 0:
        raise SystemExit(f"[revert] error: git clean src/Userspace failed:\n{clean.stderr}")
    print("[revert] restored src/Userspace", flush=True)


def release_lock(root):
    lock = root / "profiling" / "loop.lock"
    if lock.exists():
        shutil.rmtree(lock)
        print(f"[revert] released {lock}", flush=True)
        return
    print("[revert] no lock to release", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Revert a profiler optimization loop attempt")
    parser.add_argument(
        "--lock-only",
        action="store_true",
        help="release the lock; do not restore src/Userspace",
    )
    args = parser.parse_args()
    root = repo_root()
    if not args.lock_only:
        restore_userspace(root)
    else:
        print("[revert] keeping src/Userspace changes", flush=True)
    release_lock(root)


if __name__ == "__main__":
    main()
