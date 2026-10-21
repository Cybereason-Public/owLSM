#!/usr/bin/env python3
"""One pressure worker. start.py runs several of these at the same time."""

import argparse
import grp
import os
import shutil
import socket
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

from globals import Numbers, Strings, log


class Worker:
    def __init__(self, index):
        self._index = index
        self._directory = Strings.WORK_ROOT / str(os.getpid())
        self._files = self._directory / Strings.FILES_DIR
        self._dirs = self._directory / Strings.DIRS_DIR
        self._rename_a = self._directory / Strings.RENAME_A
        self._rename_b = self._directory / Strings.RENAME_B
        self._rename_forward = True
        self._namespace = Strings.NAMESPACE.format(index=index)
        self._host_veth = Strings.VETH_HOST.format(index=index)
        self._namespace_veth = Strings.VETH_NAMESPACE.format(index=index)
        self._host_ip = Strings.HOST_IP.format(index=index)
        self._namespace_ip = Strings.NAMESPACE_IP.format(index=index)
        self._port = Numbers.BASE_PORT + index
        self._groups = _two_groups()
        self._group_index = 0
        self._listener = None
        self._owlsm_pid = Strings.OWLSM_PID_FILE.read_text(encoding="utf-8").strip()
        self._shell_signal = Strings.SHELL_SIGNAL.format(pid=self._owlsm_pid)

    def run(self):
        try:
            self._prepare_files()
            self._prepare_network()
            self._start_listener()
            self._loop()
        finally:
            self._cleanup()

    def _prepare_files(self):
        self._files.mkdir(parents=True)
        self._dirs.mkdir(parents=True)
        self._rename_a.mkdir(parents=True)
        for name in range(1, Numbers.POOL_SIZE + 1):
            _create_empty(self._files / str(name))
            _create_empty(self._rename_a / str(name))
            os.mkdir(self._dirs / str(name))

    def _prepare_network(self):
        cleanup_namespace(self._index)
        _run([Strings.IP, "netns", "add", self._namespace])
        _run([
            Strings.IP, "link", "add", self._host_veth, "type", "veth",
            "peer", "name", self._namespace_veth,
        ])
        _run([Strings.IP, "addr", "add", f"{self._host_ip}/30", "dev", self._host_veth])
        _run([Strings.IP, "link", "set", self._host_veth, "up"])
        _run([Strings.IP, "link", "set", self._namespace_veth, "netns", self._namespace])
        _run([
            Strings.IP, "netns", "exec", self._namespace,
            Strings.IP, "addr", "add", f"{self._namespace_ip}/30", "dev", self._namespace_veth,
        ])
        _run([
            Strings.IP, "netns", "exec", self._namespace,
            Strings.IP, "link", "set", self._namespace_veth, "up",
        ])
        _run([
            Strings.IP, "netns", "exec", self._namespace,
            Strings.IP, "link", "set", "lo", "up",
        ])
        for command in _notrack_rules([Strings.IP, "netns", "exec", self._namespace]):
            _run(command)

    def _start_listener(self):
        self._listener = subprocess.Popen(
            [
                Strings.IP, "netns", "exec", self._namespace,
                sys.executable, str(Strings.WORKLOAD_SCRIPT),
                "--role", "listener",
                "--bind", self._namespace_ip,
                "--port", str(self._port),
            ],
            start_new_session=True,
        )
        deadline = time.monotonic() + Numbers.LISTENER_READY_SECONDS
        while time.monotonic() < deadline:
            if self._listener.poll() is not None:
                raise RuntimeError(f"listener for worker {self._index} exited before it accepted")
            try:
                self._connect()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"listener for worker {self._index} did not accept a connection")

    def _loop(self):
        log(f"worker {self._index} pressure loop for {Numbers.PRESSURE_LOOP_SECONDS}s")
        files = deque(str(name) for name in range(1, Numbers.POOL_SIZE + 1))
        directories = deque(str(name) for name in range(1, Numbers.POOL_SIZE + 1))
        next_name = Numbers.NEXT_NAME
        deadline = time.monotonic() + Numbers.PRESSURE_LOOP_SECONDS
        while time.monotonic() < deadline:
            self._touch_file(files, next_name)
            self._touch_dir(directories, next_name)
            self._connect_or_log()
            self._run_shell()
            self._rename_pool()
            next_name += 1
        log(f"worker {self._index} pressure loop finished")

    def _touch_file(self, names, next_name):
        path = self._files / str(next_name)

        def create():
            _create_empty(path)
            names.append(str(next_name))

        def write():
            file = os.open(path, os.O_WRONLY)
            try:
                os.write(file, b"p")
            finally:
                os.close(file)

        def chmod():
            mode = Numbers.FILE_MODE_A if next_name % 2 == 0 else Numbers.FILE_MODE_B
            os.chmod(path, mode)

        def chown():
            gid = self._groups[self._group_index]
            self._group_index = 1 - self._group_index
            os.chown(path, -1, gid)

        def delete_oldest():
            oldest = self._files / names.popleft()
            os.unlink(oldest)

        self._attempt("create file", create)
        self._attempt("write file", write)
        self._attempt("chmod file", chmod)
        self._attempt("chown file", chown)
        self._attempt("delete oldest file", delete_oldest)

    def _touch_dir(self, names, next_name):
        path = self._dirs / str(next_name)

        def create():
            os.mkdir(path)
            names.append(str(next_name))

        def delete_oldest():
            oldest = self._dirs / names.popleft()
            os.rmdir(oldest)

        self._attempt("create dir", create)
        self._attempt("delete oldest dir", delete_oldest)

    def _connect_or_log(self):
        self._attempt("connect", self._connect)

    def _connect(self):
        connection = socket.create_connection(
            (self._namespace_ip, self._port),
            Numbers.CONNECT_TIMEOUT_SECONDS,
        )
        try:
            connection.sendall(b"x")
        finally:
            connection.close()

    def _run_shell(self):
        def run():
            subprocess.run(
                [Strings.SHELL, "-c", self._shell_signal],
                timeout=Numbers.SHELL_TIMEOUT_SECONDS,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        self._attempt("shell signal", run)

    def _rename_pool(self):
        source = self._rename_a if self._rename_forward else self._rename_b
        destination = self._rename_b if self._rename_forward else self._rename_a

        def rename():
            os.rename(source, destination)
            self._rename_forward = not self._rename_forward

        self._attempt("rename", rename)

    def _attempt(self, label, action):
        try:
            action()
        except Exception as error:
            log(f"worker {self._index} {label} failed: {error}")

    def _cleanup(self):
        if self._listener is not None and self._listener.poll() is None:
            _kill_group(self._listener.pid)
            try:
                self._listener.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        cleanup_namespace(self._index)
        if self._directory.exists():
            shutil.rmtree(self._directory, ignore_errors=True)


def setup_notrack():
    for command in _notrack_rules([], delete_first=True):
        _run(command)


def teardown_notrack():
    for command in _notrack_rules([], action="-D"):
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _notrack_rules(prefix, action="-I", delete_first=False):
    for chain in ("PREROUTING", "OUTPUT"):
        for flag in ("-s", "-d"):
            command = [*prefix, Strings.IPTABLES, "-t", "raw", action, chain, flag, Strings.PRESSURE_SUBNET, "-j", "CT", "--notrack"]
            if delete_first:
                stale = [*prefix, Strings.IPTABLES, "-t", "raw", "-D", chain, flag, Strings.PRESSURE_SUBNET, "-j", "CT", "--notrack"]
                subprocess.run(stale, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            yield command


def cleanup_namespace(index):
    namespace = Strings.NAMESPACE.format(index=index)
    host_veth = Strings.VETH_HOST.format(index=index)
    if Path("/run/netns", namespace).exists():
        result = subprocess.run(
            [Strings.IP, "netns", "pids", namespace],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if result.returncode == 0:
            for pid_text in result.stdout.split():
                try:
                    os.kill(int(pid_text), 9)
                except (ProcessLookupError, PermissionError, ValueError):
                    continue
    subprocess.run([Strings.IP, "link", "delete", host_veth], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([Strings.IP, "netns", "delete", namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def worker_count():
    cpu_count = os.cpu_count() or 1
    count = round(cpu_count * Numbers.WORKER_CPU_MULTIPLIER)
    if count < 1:
        raise RuntimeError(f"{cpu_count} CPUs is not enough to start a pressure worker")
    return count


def serve(bind, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind, port))
    server.listen(128)
    server.settimeout(1.0)
    while True:
        try:
            connection, _address = server.accept()
        except socket.timeout:
            continue
        try:
            connection.recv(16)
        finally:
            connection.close()


def _create_empty(path):
    file = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(file)


def _two_groups():
    groups = []
    for name in (Strings.GROUP_ROOT, Strings.GROUP_OTHER):
        try:
            gid = grp.getgrnam(name).gr_gid
        except KeyError:
            continue
        if gid not in groups:
            groups.append(gid)
    if len(groups) < 2:
        for entry in grp.getgrall():
            if entry.gr_gid not in groups:
                groups.append(entry.gr_gid)
            if len(groups) == 2:
                break
    if len(groups) < 2:
        raise RuntimeError("need two groups for chown")
    return groups


def _run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")


def _kill_group(pid):
    try:
        os.killpg(pid, 9)
    except ProcessLookupError:
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["worker", "listener"], default="worker")
    parser.add_argument("--index", type=int)
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    try:
        if args.role == "listener":
            serve(args.bind, args.port)
            return
        Worker(args.index).run()
    except Exception as error:
        log(f"worker failed: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
