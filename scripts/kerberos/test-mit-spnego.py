#!/usr/bin/env python3
"""Run the ignored Rust proof in a disposable, loopback-only MIT realm.

Linux prerequisites: krb5-kdc, krb5-admin-server, krb5-user, libkrb5-dev,
python3-gssapi; run with /usr/bin/python3. No system realm is changed. No
passwords are needed: kadmin generates random client/service keys and kinit
uses a private client keytab. All runtime material is removed in finally.

Expired tickets remain UNPROVEN: krb5 1.0.0 exposes no acceptor clock override,
MIT's initiator will not use an expired credential, and this proof neither
sleeps until expiry nor changes clocks/forges tickets. An authenticator-skew
or tamper failure is not evidence of expired-ticket validation.
"""
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
REALM = "QID.MIT.TEST"
SERVICE = f"HTTP/acceptor.qid.test@{REALM}"
WRONG_SERVICE = f"HTTP/other.qid.test@{REALM}"
CLIENT = f"client@{REALM}"


class FixtureError(Exception):
    pass


def stop(process):
    # Children start in their own session; also reap descendants (GSS peer).
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def run(args, env, stage, timeout=15, visible=False, input_data=None):
    process = subprocess.Popen(
        args, cwd=ROOT, env=env, start_new_session=True,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=None if visible else subprocess.DEVNULL,
        stderr=None if visible else subprocess.DEVNULL,
    )
    try:
        process.communicate(input=input_data, timeout=timeout)
        if process.returncode:
            raise FixtureError(f"{stage} failed (details suppressed)")
    except subprocess.TimeoutExpired:
        raise FixtureError(f"{stage} exceeded its deadline") from None
    finally:
        stop(process)


def interrupt(_signum, _frame):
    raise FixtureError("interrupted")


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    env = os.environ.copy()
    env["PATH"] = env.get("PATH", "") + ":/usr/sbin:/usr/local/sbin"
    tools = ["krb5kdc", "kdb5_util", "kadmin.local", "kinit", "krb5-config", "cargo"]
    missing = [tool for tool in tools if not shutil.which(tool, path=env["PATH"])]
    if missing:
        raise FixtureError("missing prerequisites: " + ", ".join(missing))
    vendor = subprocess.check_output(
        ["krb5-config", "--vendor"], env=env, timeout=5, stderr=subprocess.DEVNULL
    )
    if b"Massachusetts Institute of Technology" not in vendor:
        raise FixtureError("the fixture requires MIT krb5, not another GSS provider")
    run([sys.executable, "-c", "import gssapi"], env, "python3-gssapi prerequisite")
    test = ["cargo", "test", "-p", "qid-federation", "--locked", "--test", "kerberos_mit"]
    # Compile before creating secrets or starting the KDC. Bound cold builds too.
    run(test + ["--no-run"], env, "Rust test build", timeout=600, visible=True)
    with tempfile.TemporaryDirectory(prefix="qid-mit-") as temp:
        directory = Path(temp)
        # A released ephemeral TCP port has a small bind race. Fail on KDC
        # startup failure rather than talking to an unrelated existing realm.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        conf = directory / "krb5.conf"
        profile = directory / "kdc.conf"
        conf.write_text(f"""[libdefaults]
 default_realm = {REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
 udp_preference_limit = 1
 kdc_timeout = 2000
 max_retries = 1
[realms]
 {REALM} = {{
  kdc = 127.0.0.1:{port}
 }}
""")
        profile.write_text(f"""[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[realms]
 {REALM} = {{
  database_name = {directory}/principal
  key_stash_file = {directory}/stash
  acl_file = {directory}/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
  max_life = 1h
 }}
[logging]
 kdc = FILE:{directory}/kdc.log
 admin_server = FILE:{directory}/admin.log
""")
        # Do not inherit unrelated ticket/keytab/trace/plugin environment settings.
        env = {k: v for k, v in env.items() if not k.startswith(("KRB5", "GSS_"))}
        env.update({
            "KRB5_CONFIG": str(conf), "KRB5_KDC_PROFILE": str(profile),
            "KRB5CCNAME": f"FILE:{directory}/ccache",
            "KRB5_KTNAME": f"FILE:{directory}/service.keytab",
            "KRB5_CLIENT_KTNAME": f"FILE:{directory}/client.keytab",
            # Deliberately disable the environment-sensitive default: only the
            # explicit QID replay store must protect the Rust acceptor.
            "KRB5RCACHETYPE": "none", "GSS_USE_PROXY": "0",
            "QID_MIT_KEYTAB": str(directory / "service.keytab"),
            "QID_MIT_PYTHON": sys.executable,
        })
        # Feed a generated master password on stdin, never argv or diagnostics.
        master = os.urandom(32).hex().encode()
        run(["kdb5_util", "create", "-s", "-r", REALM], env, "realm creation",
            input_data=master + b"\n" + master + b"\n")
        del master
        for principal in [CLIENT, SERVICE, WRONG_SERVICE]:
            run(["kadmin.local", "-r", REALM, "-q", f"addprinc -randkey {principal}"],
                env, "principal creation")
        for principal, filename in [(CLIENT, "client.keytab"), (SERVICE, "service.keytab")]:
            run(["kadmin.local", "-r", REALM, "-q",
                 f"ktadd -k {directory}/{filename} {principal}"], env, "keytab creation")
        kdc = subprocess.Popen(
            ["krb5kdc", "-n", "-r", REALM, "-P", str(directory / "kdc.pid")],
            env=env, cwd=directory, start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if kdc.poll() is not None:
                    raise FixtureError("MIT KDC exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise FixtureError("MIT KDC readiness deadline exceeded") from None
                    time.sleep(0.05)  # Readiness polling only; never ticket expiry.
            run(["kinit", "-k", "-t", str(directory / "client.keytab"), CLIENT],
                env, "MIT client login")
            run(test + ["--", "--ignored", "--exact", "mit_spnego_acceptor_proof"],
                env, "MIT SPNEGO proof", timeout=60, visible=True)
            print("MIT SPNEGO: mutual handshake, replay, tamper and wrong-service checks passed")
            print("Expired-ticket refusal: UNPROVEN (see fixture source for limitations)")
        finally:
            stop(kdc)


if __name__ == "__main__":
    try:
        main()
    except FixtureError as error:
        print(f"MIT fixture: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # No traceback: subprocess errors may retain provisioning inputs.
        print("MIT fixture failed (details suppressed)", file=sys.stderr)
        sys.exit(1)
