# SPDX-License-Identifier: BUSL-1.1
"""Install the bus hub with real accounts on a Linux runner, use it over its socket, remove it.

Runs as the runner user and uses sudo inside the runner only. The bus wheel goes alone into a
new environment. install creates the bus account, the gateway account and the socket group;
two more accounts are made for the test: one in the socket group that is not the gateway, and
one outside it. The daemon runs as the bus account, without systemd. Keys are generated here,
reach the hub as sha256 only and reach the clients on stdin; none is printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

BUS, GATEWAY, GROUP = "ihub-bus", "ihub-gw", "ihub-sock"
MEMBER, OUTSIDER = "ihub-member", "ihub-outsider"
VENV = Path("/opt/integrity-llm-bus-hub-check")
ETC, STATE, RUNTIME = Path("/etc/integrity-llm-bus-check"), Path("/var/lib/integrity-llm-bus-check"), Path("/run/integrity-llm-bus-check")
PYTHON, TOOL = str(VENV / "bin" / "python"), str(VENV / "bin" / "integrity-llm-bus-hub")

# One request on stdin: {"socket": path, "request": {...}}. Prints the hub's answer, or how connect failed.
CLIENT = r"""
import json, socket, sys
doc = json.loads(sys.stdin.read())
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(30)
try:
    s.connect(doc["socket"])
except OSError as exc:
    print(json.dumps({"connect_error": type(exc).__name__})); sys.exit(0)
s.sendall((json.dumps(doc["request"]) + "\n").encode())
buf = b""
while not buf.endswith(b"\n"):
    c = s.recv(65536)
    if not c:
        break
    buf += c
print(buf.decode())
"""


def run(argv, expect=(0,), stdin=None, timeout=300):
    done = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
    if done.returncode not in expect:
        raise SystemExit(f"{argv[:4]} exited {done.returncode}, expected {expect}\n{done.stdout}\n{done.stderr}")
    return done


def sudo(*argv, **kw):
    return run(["sudo", "-n", *argv], **kw)


def hub(*argv, expect=(0,)):
    done = sudo(TOOL, *argv, expect=expect)
    return json.loads(done.stdout), done.returncode


def exists(kind, name):
    return subprocess.run(["getent", kind, name], capture_output=True, check=False).returncode == 0


def ask(user, request):
    doc = {"socket": str(RUNTIME / "core.sock"), "request": {"v": 1, **request}}
    done = sudo("-u", user, PYTHON, "-I", "-c", CLIENT, stdin=json.dumps(doc), timeout=60)
    return json.loads(done.stdout)


def expect_error(answer, text, case):
    if answer.get("ok") is not False or text not in answer.get("error", ""):
        raise SystemExit(f"{case}: expected a refusal containing {text!r}, got {answer}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--wheel", required=True, help="the built integrity_llm_bus wheel")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("Linux only")

    sudo(sys.executable, "-m", "venv", str(VENV))
    sudo(PYTHON, "-m", "pip", "install", "--quiet", str(Path(args.wheel).resolve()))
    installed = {item["name"].lower().replace("_", "-")
                 for item in json.loads(run([PYTHON, "-m", "pip", "list", "--format", "json"]).stdout)}
    others = sorted(n for n in installed if n.startswith("integrity") and n != "integrity-llm-bus")
    if "integrity-llm-bus" not in installed or others:
        raise SystemExit(f"expected integrity-llm-bus alone, found {sorted(installed)}")

    tokens = {name: secrets.token_urlsafe(32) for name in ("local-codex", "local-revoked")}
    digest = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in tokens.items()}
    ops = ["send", "poll", "get", "ack", "status"]
    principals = {"principals": {
        "vendor-claude": {"vendor": "claude", "account": "example-a", "addresses": ["claude"], "ops": ops, "write": True},
        "vendor-grok-ro": {"vendor": "grok", "account": "example-b", "addresses": ["grok"], "ops": ops, "write": False},
        "vendor-old": {"vendor": "codex", "account": "example-c", "addresses": ["codexfc"], "ops": ops, "write": True,
                       "revoked": True},
        "local-codex": {"key_sha256": digest["local-codex"], "vendor": "codex", "account": "example-d",
                        "addresses": ["codex"], "ops": ops, "write": True},
        "local-revoked": {"key_sha256": digest["local-revoked"], "vendor": "codex", "account": "example-e",
                          "addresses": ["codex"], "ops": ops, "write": True, "revoked": True},
    }, "accounts": {}}
    with tempfile.TemporaryDirectory() as work:
        keys = Path(work) / "principals.json"
        keys.write_text(json.dumps(principals), encoding="utf-8")
        os.chmod(keys, 0o644)
        report, _ = hub("install", "--etc", str(ETC), "--state", str(STATE), "--runtime", str(RUNTIME),
                        "--bus-user", BUS, "--gateway-user", GATEWAY, "--socket-group", GROUP,
                        "--principals", str(keys))
    if report["status"] != "installed" or not all(exists("passwd", u) for u in (BUS, GATEWAY)) or not exists("group", GROUP):
        raise SystemExit(f"install: {report}")
    again, code = hub("install", "--etc", str(ETC), "--state", str(STATE), "--runtime", str(RUNTIME),
                      "--bus-user", BUS, "--gateway-user", GATEWAY, "--socket-group", GROUP,
                      "--principals", "/dev/null", expect=(2,))
    if "exists" not in again["error"]:
        raise SystemExit(f"a second install must refuse: {again}")
    report, _ = hub("doctor", "--etc", str(ETC))
    if report["status"] != "passed":
        raise SystemExit(f"doctor after install: {report}")

    sudo("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--groups", GROUP, MEMBER)
    sudo("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", OUTSIDER)
    start = report["start"]
    environment = [f"{k}={v}" for k, v in start["environment"].items()]
    daemon = subprocess.Popen(["sudo", "-n", "-u", start["user"], "env", "-i", *environment, *start["argv"]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sock = RUNTIME / "core.sock"
    for _ in range(100):
        if daemon.poll() is not None:
            raise SystemExit(f"the daemon exited {daemon.returncode}: {daemon.stderr.read()[-2000:]}")
        if sudo("test", "-S", str(sock), expect=(0, 1)).returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise SystemExit("the daemon did not open its socket")

    results = {}
    sent = uuid.uuid4().hex[:16]
    answer = ask(GATEWAY, {"op": "send", "vendor": "vendor-claude",
                           "args": {"to": "codex", "id": sent, "body": "hello from the gateway"}})
    if answer.get("ok") is not True or answer["result"]["message"]["from"] != "claude":
        raise SystemExit(f"gateway send: {answer}")
    results["gateway send"] = "ok"
    answer = ask(MEMBER, {"op": "poll", "token": tokens["local-codex"], "args": {}})
    if answer.get("ok") is not True or not any(m["id"] == sent for m in answer["result"]["queue"]):
        raise SystemExit(f"local key poll: {answer}")
    results["local key poll"] = "ok, the gateway's message is in the queue"
    for case, user, request, text in (
        ("revoked vendor", GATEWAY, {"op": "poll", "vendor": "vendor-old", "args": {}}, "key revoked"),
        ("unknown vendor", GATEWAY, {"op": "poll", "vendor": "vendor-none", "args": {}}, "unknown vendor key"),
        ("read-only vendor writes", GATEWAY, {"op": "send", "vendor": "vendor-grok-ro",
                                              "args": {"to": "codex", "id": uuid.uuid4().hex[:16], "body": "x"}},
         "read-only key"),
        ("gateway without vendor", GATEWAY, {"op": "poll", "token": tokens["local-codex"], "args": {}},
         "gateway sent no valid vendor id"),
        ("vendor named by a non-gateway uid", MEMBER, {"op": "poll", "vendor": "vendor-claude", "args": {}},
         "only the SSH gateway may name a vendor"),
        ("unknown key", MEMBER, {"op": "poll", "token": secrets.token_urlsafe(32), "args": {}}, "unknown vendor key"),
        ("revoked key", MEMBER, {"op": "poll", "token": tokens["local-revoked"], "args": {}}, "key revoked"),
    ):
        expect_error(ask(user, request), text, case)
        results[case] = f"refused: {text}"
    answer = ask(OUTSIDER, {"op": "poll", "args": {}})
    if answer.get("connect_error") != "PermissionError":
        raise SystemExit(f"an account outside the socket group must not connect: {answer}")
    results["account outside the socket group"] = "connect refused: PermissionError"

    refused, code = hub("uninstall", "--etc", str(ETC), "--yes", expect=(3,))
    if refused["status"] != "refused":
        raise SystemExit(f"uninstall while the daemon runs must refuse: {refused}")
    sudo("pkill", "-TERM", "-u", BUS, expect=(0,))
    try:
        daemon.wait(timeout=30)
    except subprocess.TimeoutExpired:
        raise SystemExit("the daemon did not stop") from None

    # a process of the gateway account stops the removal too, before anything is removed
    holder = subprocess.Popen(["sudo", "-n", "-u", GATEWAY, "sleep", "300"])
    try:
        for _ in range(100):
            if subprocess.run(["pgrep", "-u", GATEWAY], capture_output=True, check=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise SystemExit("the gateway account process did not start")
        refused, code = hub("uninstall", "--etc", str(ETC), "--yes", expect=(3,))
        kept = sudo("test", "-d", str(STATE), expect=(0, 1)).returncode == 0 and exists("passwd", BUS)
        if refused["status"] != "refused" or GATEWAY not in refused["reason"] or not kept:
            raise SystemExit(f"uninstall while a gateway process runs must refuse and keep everything: {refused}")
        results["uninstall while a gateway account process runs"] = "refused, nothing removed"
    finally:
        sudo("pkill", "-KILL", "-u", GATEWAY, expect=(0, 1))
        holder.wait(timeout=30)

    # requests that reached the hub: 9 answered above, plus the service-start record
    chain = json.loads(sudo("-u", BUS, "env", "-i", *environment, PYTHON, "-I", "-B",
                            str(Path(start["argv"][-1]).with_name("bus_journal.py")), str(STATE / "journal")).stdout)
    if not chain.get("ok") or chain["records"] != 10:
        raise SystemExit(f"journal chain: {chain}")
    report, _ = hub("doctor", "--etc", str(ETC))
    if report["status"] != "passed":
        raise SystemExit(f"doctor after the run: {report}")

    for user in (MEMBER, OUTSIDER):
        sudo("userdel", user)
    dry, _ = hub("uninstall", "--etc", str(ETC))
    if dry["status"] != "dry-run" or not sudo("test", "-d", str(STATE), expect=(0, 1)).returncode == 0:
        raise SystemExit(f"uninstall without --yes must remove nothing: {dry}")
    removed, _ = hub("uninstall", "--etc", str(ETC), "--yes")
    report, code = hub("doctor", "--etc", str(ETC), expect=(3,))
    left = [p for p in (ETC, STATE, RUNTIME) if sudo("test", "-e", str(p), expect=(0, 1)).returncode == 0]
    accounts = [n for n in (BUS, GATEWAY) if exists("passwd", n)] + [n for n in (GROUP, BUS) if exists("group", n)]
    if removed["status"] != "removed" or report["status"] != "not-installed" or left or accounts:
        raise SystemExit(f"after uninstall: {removed} {report} left={left} accounts={accounts}")
    sudo(PYTHON, "-m", "pip", "uninstall", "--quiet", "--yes", "integrity-llm-bus")
    if Path(TOOL).exists():
        raise SystemExit("pip uninstall left the command behind")
    sudo("rm", "-rf", "--", str(VENV))
    print(json.dumps({"passed": True, "requests": results, "journal_records": chain["records"],
                      "doctor_after_uninstall": report["status"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
