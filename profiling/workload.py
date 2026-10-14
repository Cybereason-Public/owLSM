#!/usr/bin/env python3
"""One copy of the file, exec, and network pressure loop.

start.py runs four processes of this file. Each process prepares its own
work/<n>/ directory, then loops until the finish file appears.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from collections import deque
from pathlib import Path


POOL_SIZE = 200
RENAME_COUNT = 20
CONNECT_TIMEOUT_SECONDS = 2


class Workload:
    def __init__(self, index, work_root, finish_file):
        self._index = index
        self._directory = Path(work_root) / str(index)
        self._pool = self._directory / "pool"
        self._renames = self._directory / "renames"
        self._finish = Path(finish_file)
        self._namespace = f"owlsm-w{index}"
        self._host_veth = f"owl{index}h"
        self._namespace_veth = f"owl{index}n"
        self._host_ip = f"10.200.{index}.1"
        self._namespace_ip = f"10.200.{index}.2"
        self._port = 19000 + index
        self._listener = None

    def run(self):
        try:
            self._prepare_files()
            self._prepare_network()
            self._start_listener()
            self._loop()
        finally:
            self._cleanup()

    def _prepare_files(self):
        self._pool.mkdir(parents=True, exist_ok=True)
        self._renames.mkdir(parents=True, exist_ok=True)
        for index in range(POOL_SIZE):
            (self._pool / f"f{index}").write_bytes(b"p")
        for index in range(POOL_SIZE):
            (self._renames / f"r{index}").write_bytes(b"p")

    def _prepare_network(self):
        self._run(["ip", "netns", "add", self._namespace])
        self._run([
            "ip", "link", "add", self._host_veth, "type", "veth", "peer", "name", self._namespace_veth
        ])
        self._run(["ip", "link", "set", self._namespace_veth, "netns", self._namespace])
        self._run(["ip", "addr", "add", f"{self._host_ip}/30", "dev", self._host_veth])
        self._run(["ip", "link", "set", self._host_veth, "up"])
        self._run(["ip", "netns", "exec", self._namespace, "ip", "link", "set", "lo", "up"])
        self._run([
            "ip", "netns", "exec", self._namespace,
            "ip", "addr", "add", f"{self._namespace_ip}/30", "dev", self._namespace_veth,
        ])
        self._run([
            "ip", "netns", "exec", self._namespace, "ip", "link", "set", self._namespace_veth, "up"
        ])

    def _start_listener(self):
        self._listener = subprocess.Popen(
            [
                "ip", "netns", "exec", self._namespace,
                sys.executable, str(Path(__file__).resolve()),
                "--role", "listener",
                "--bind", self._namespace_ip,
                "--port", str(self._port),
                "--finish", str(self._finish),
            ],
            start_new_session=True,
        )
        self._wait_until_listener_accepts()

    def _wait_until_listener_accepts(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self._listener.poll() is not None:
                raise RuntimeError(f"listener for worker {self._index} exited before it accepted")
            try:
                self._connect_and_send()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"listener for worker {self._index} did not accept a connection")

    def _loop(self):
        names = deque(f"f{index}" for index in range(POOL_SIZE))
        next_id = POOL_SIZE
        while not self._finish.exists():
            self._touch_pool_file(names, next_id)
            next_id += 1
            self._make_and_remove_directory()
            self._rename_out_and_back()
            subprocess.run(["/bin/true"], check=True)
            self._connect_and_send()

    def _touch_pool_file(self, names, next_id):
        name = f"f{next_id}"
        path = self._pool / name
        path.write_bytes(b"p")
        path.read_bytes()
        path.chmod(0o640)
        os.chown(path, os.getuid(), os.getgid())
        oldest = self._pool / names.popleft()
        oldest.unlink()
        names.append(name)

    def _make_and_remove_directory(self):
        created = self._pool / "once"
        created.mkdir()
        created.rmdir()

    def _rename_out_and_back(self):
        for index in range(RENAME_COUNT):
            source = self._renames / f"r{index}"
            sibling = self._renames / f"r{index}.x"
            source.rename(sibling)
            sibling.rename(source)

    def _connect_and_send(self):
        with socket.create_connection(
            (self._namespace_ip, self._port), timeout=CONNECT_TIMEOUT_SECONDS
        ) as connection:
            connection.sendall(b"x")

    def _cleanup(self):
        try:
            self._stop_listener()
        except OSError as error:
            print(f"workload {self._index} listener cleanup: {error}", file=sys.stderr)
        subprocess.run(["ip", "link", "delete", self._host_veth], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "netns", "delete", self._namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._directory.exists():
            shutil.rmtree(self._directory, ignore_errors=True)

    def _stop_listener(self):
        if self._listener is None or self._listener.poll() is not None:
            return
        self._listener.terminate()
        try:
            self._listener.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._listener.kill()
            self._listener.wait(timeout=5)

    def _run(self, command):
        subprocess.run(command, check=True)


def serve(bind, port, finish_file):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, port))
        server.listen()
        server.settimeout(0.5)
        while not finish_file.exists():
            try:
                connection, _address = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(1)
                try:
                    connection.recv(16)
                except socket.timeout:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("worker", "listener"), default="worker")
    parser.add_argument("--index", type=int)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--finish", type=Path)
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    if args.role == "listener":
        serve(args.bind, args.port, args.finish)
        return

    if args.index is None or args.work_root is None or args.finish is None:
        parser.error("worker role requires --index, --work-root, and --finish")
    Workload(args.index, args.work_root, args.finish).run()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"workload failed: {error}", file=sys.stderr)
        sys.exit(1)
