#!/usr/bin/env python3
"""Wait for /tmp/finish, then stop owLSM. This process is the only protected and excluded pid."""

import os
import signal
import time
from pathlib import Path

from globals import Numbers, Strings, log


def main():
    log("owlsm_killer waiting for the finish file")
    parent = os.getppid()
    while not Strings.FINISH_FILE.exists():
        if os.getppid() != parent:
            log("owlsm_killer's parent died before finish, stopping owlsm anyway")
            _stop_owlsm()
            return
        time.sleep(Numbers.KILLER_POLL_SECONDS)

    _stop_owlsm()


def _stop_owlsm():
    pid = _read_pid()
    if pid is None:
        log(f"owlsm_killer did not find a pid in {Strings.OWLSM_PID_FILE}")
        return

    log(f"owlsm_killer sending SIGINT to {pid}")
    _signal(pid, signal.SIGINT)
    deadline = time.monotonic() + Numbers.KILLER_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            log(f"owlsm_killer saw {pid} exit")
            return
        time.sleep(Numbers.KILLER_CHECK_SECONDS)

    if _is_alive(pid):
        log(f"owlsm_killer sending SIGKILL to {pid}")
        _signal(pid, signal.SIGKILL)


def _read_pid():
    if not Strings.OWLSM_PID_FILE.exists():
        return None
    text = Strings.OWLSM_PID_FILE.read_text(encoding="utf-8").strip()
    if not text:
        return None
    return int(text)


def _signal(pid, sig):
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return


def _is_alive(pid):
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        stat = stat_path.read_text(encoding="utf-8")
    except OSError:
        return False
    end = stat.rfind(")")
    if end < 0 or end + 2 >= len(stat):
        return True
    return stat[end + 2] != "Z"


if __name__ == "__main__":
    main()
