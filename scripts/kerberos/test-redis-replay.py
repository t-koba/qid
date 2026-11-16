#!/usr/bin/env python3
"""Isolated local-AOF qualification, not a production Redis deployment.

Requires Docker, Python 3 and Cargo. Uses the BSD-licensed Redis 7.2.4 release
with no RDB snapshots and appendfsync everysec, so SET alone is insufficient.
All containers and anonymous data volumes are removed, including on failure.
Only loopback ports are published; Redis logs and endpoints are never printed.
"""
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "redis:7.2.4-bookworm"
TEST = ["cargo", "test", "--locked", "-p", "qid-federation", "--test", "kerberos_replay"]


class FixtureError(Exception):
    pass


def run(args, stage, timeout=20, env=None, visible=False):
    process = subprocess.Popen(
        args, cwd=ROOT, env=env, start_new_session=True,
        stdin=subprocess.DEVNULL, stderr=None if visible else subprocess.DEVNULL,
        stdout=None if visible else subprocess.PIPE,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
        if process.returncode:
            raise FixtureError(f"{stage} failed (details suppressed)")
        return (output or b"").decode("utf-8")
    except subprocess.TimeoutExpired:
        raise FixtureError(f"{stage} exceeded its deadline") from None
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def interrupt(_signum, _frame):
    raise FixtureError("interrupted")


def start(name):
    run(["docker", "start", name], "Redis start")
    published = run(["docker", "port", name, "6379/tcp"], "loopback port lookup").strip()
    if not published.startswith("127.0.0.1:") or "\n" in published:
        raise FixtureError("unexpected port binding")
    port = int(published.split(":")[1])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as peer:
                peer.sendall(b"*1\r\n$4\r\nPING\r\n")
                if peer.recv(64) == b"+PONG\r\n":
                    return f"redis://127.0.0.1:{port}/"
        except OSError:
            pass
        time.sleep(0.1)
    raise FixtureError("Redis readiness exceeded its deadline")


def phase(url, name):
    env = os.environ.copy()
    env["QID_TEST_REDIS_URL"] = url
    env["QID_TEST_REDIS_PHASE"] = name
    run(TEST + ["--", "--ignored", "--exact", "redis_local_aof_qualification"],
        name, env=env, visible=True)


def main():
    missing = [tool for tool in ("docker", "cargo") if not shutil.which(tool)]
    if missing:
        raise FixtureError("missing prerequisites: " + ", ".join(missing))
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    # Compile before allocating Redis resources. Subsequent phases are bounded
    # to 20 seconds, including TCP stalls; WAITAOF itself waits at most 2000 ms.
    run(TEST + ["--no-run"], "Rust test build", timeout=600, visible=True)
    run(["cargo", "test", "--locked", "-p", "qid-core", "--features", "redis-cache",
         "--test", "redis_durability"], "RESP contract checks", timeout=600, visible=True)
    run(TEST, "existing replay checks", visible=True)
    run(["docker", "pull", IMAGE], "pinned Redis image pull", timeout=120)
    for mode in ("aof", "aof-disabled", "waitaof-unavailable"):
        name = "qid-replay-" + uuid.uuid4().hex
        try:
            command = [
                "docker", "create", "--name", name, "--publish", "127.0.0.1::6379",
                "--volume", "/data", IMAGE, "redis-server",
                "--bind", "0.0.0.0", "--protected-mode", "no", "--save", "",
                "--dir", "/data", "--appendonly", "no" if mode == "aof-disabled" else "yes",
                "--appendfsync", "everysec", "--auto-aof-rewrite-percentage", "0",
                "--loglevel", "warning",
            ]
            if mode == "waitaof-unavailable":
                # Simulate an unsupported/disabled command on the same pinned
                # binary; this is not a claim to have tested an older release.
                command += ["--rename-command", "WAITAOF", ""]
            run(command, "Redis fixture creation")
            url = start(name)
            version = run(["docker", "exec", name, "redis-server", "--version"],
                          "Redis version check")
            if not version.startswith("Redis server v=7.2.4 "):
                raise FixtureError("unexpected Redis version")
            if mode == "aof":
                phase(url, "before-restart")
                # No graceful SHUTDOWN/fsync, no RDB fallback, no new volume.
                run(["docker", "kill", "--signal", "KILL", name], "Redis crash")
                code = run(["docker", "inspect", "--format", "{{.State.ExitCode}}", name],
                           "Redis crash status").strip()
                if code != "137":
                    raise FixtureError("Redis did not exit from SIGKILL")
                phase(start(name), "after-restart")
            else:
                phase(url, "unavailable")
            print(f"Redis qualification passed: {mode}", flush=True)
        finally:
            # -v removes the unreferenced anonymous AOF volume. Suppress all
            # daemon output, never dump Redis logs as part of diagnostics.
            run(["docker", "rm", "--force", "--volumes", name], "Redis cleanup")


if __name__ == "__main__":
    try:
        main()
    except FixtureError as error:
        print(f"Redis qualification failed: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError):
        print("Redis qualification failed (fixture details suppressed)", file=sys.stderr)
        sys.exit(1)
