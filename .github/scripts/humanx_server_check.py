# SPDX-License-Identifier: BUSL-1.1
"""Install HumanX with real accounts next to the bus hub on a Linux runner, use it, remove it.

Runs as the runner user and uses sudo inside the runner only. The bus wheel and the HumanX
wheel go alone into a new environment. The bus hub is installed first, as in
bus_hub_accounts_check.py; then integrity-humanx-server install creates the web account, the
read-only gateway account and the gateway socket group. The gateway and the web run as their
accounts, without systemd. The web listens on 127.0.0.1 only. Keys are generated here, reach the
hub as sha256 only and reach the web through its key file; none is printed. The Integrity
snapshot is a synthetic database written here. No switch, database server or SSH host is used.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

BUS, BUS_GATEWAY, BUS_GROUP = "ihub-bus", "ihub-gw", "ihub-sock"
WEB, GATEWAY, GROUP = "ihx-web", "ihx-ro", "ihx-ro-sock"
VENDOR_SIDE, OUTSIDER = "ihx-vendor", "ihx-outsider"
VENV = Path("/opt/integrity-humanx-check")
HUB_ETC, HUB_STATE, HUB_RUNTIME = (Path("/etc/integrity-llm-bus-hx"), Path("/var/lib/integrity-llm-bus-hx"),
                                   Path("/run/integrity-llm-bus-hx"))
ETC, STATE, RUNTIME = Path("/etc/integrity-humanx-check"), Path("/var/lib/integrity-humanx-check"), Path("/run/integrity-humanx-check")
PYTHON = str(VENV / "bin" / "python")
HUB_TOOL, TOOL = str(VENV / "bin" / "integrity-llm-bus-hub"), str(VENV / "bin" / "integrity-humanx-server")
OPERATOR, HUMAN, ROOM_VENDOR = "ci", "human-ci", "room-ci-claude"
HOST, PORT = "127.0.0.1", 18890

# One request on stdin: {"socket": path, "request": {...}}. Prints the answer, or how connect failed.
CLIENT = r"""
import json, socket, sys
doc = json.loads(sys.stdin.read())
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(60)
try:
    s.connect(doc["socket"])
except OSError as exc:
    print(json.dumps({"connect_error": type(exc).__name__})); sys.exit(0)
s.sendall((json.dumps(doc["request"], ensure_ascii=False) + "\n").encode())
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


def tool(path, *argv, expect=(0,)):
    done = sudo(path, *argv, expect=expect)
    return json.loads(done.stdout), done.returncode


def exists(kind, name):
    return subprocess.run(["getent", kind, name], capture_output=True, check=False).returncode == 0


def ask(user, sock, request):
    done = sudo("-u", user, PYTHON, "-I", "-c", CLIENT, stdin=json.dumps({"socket": str(sock), "request": request}),
                timeout=90)
    return json.loads(done.stdout)


def expect_error(answer, text, case):
    if answer.get("ok") is not False or text not in str(answer.get("error", "")):
        raise SystemExit(f"{case}: expected a refusal containing {text!r}, got {answer}")


def http_call(method, path, body=None, headers=None, source=None):
    connection = http.client.HTTPConnection(HOST, PORT, timeout=60,
                                            source_address=(source, 0) if source else None)
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    connection.request(method, path, body=data, headers={**({"Content-Type": "application/json"} if data else {}),
                                                         **(headers or {})})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, dict(response.getheaders()), payload


def http_json(method, path, body=None, headers=None):
    status, _headers, payload = http_call(method, path, body, headers)
    if status != 200:
        raise SystemExit(f"{method} {path}: HTTP {status}")
    return json.loads(payload)


def start(report, user):
    command = report["start"][user]
    environment = [f"{k}={v}" for k, v in command["environment"].items()]
    return subprocess.Popen(["sudo", "-n", "-u", command["user"], "env", "-i", *environment, *command["argv"]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def wait_for(process, ready, what):
    for _ in range(150):
        if process.poll() is not None:
            raise SystemExit(f"{what} exited {process.returncode}: {process.stderr.read()[-2000:]}")
        if ready():
            return
        time.sleep(0.2)
    raise SystemExit(f"{what} did not become ready")


def port_open():
    try:
        socket.create_connection((HOST, PORT), timeout=1).close()
        return True
    except OSError:
        return False


def synthetic_snapshot(path: Path) -> int:
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, ts_utc TEXT, actor TEXT, action TEXT, summary TEXT, "
               "details TEXT, tags TEXT)")
    rows = [(n, f"2026-01-0{n}T00:00:00Z", "example-agent", "note", f"invented event {n}", "{}", "example")
            for n in (1, 2, 3)]
    db.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?)", rows)
    db.commit()
    db.close()
    return len(rows)


def stop(user, process):
    sudo("pkill", "-TERM", "-u", user, expect=(0, 1))
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"the processes of {user} did not stop") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bus-wheel", required=True)
    parser.add_argument("--humanx-wheel", required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("Linux only")

    sudo(sys.executable, "-m", "venv", str(VENV))
    sudo(PYTHON, "-m", "pip", "install", "--quiet", str(Path(args.bus_wheel).resolve()),
         str(Path(args.humanx_wheel).resolve()))
    installed = {item["name"].lower().replace("_", "-")
                 for item in json.loads(run([PYTHON, "-m", "pip", "list", "--format", "json"]).stdout)}
    ours = sorted(n for n in installed if n.startswith("integrity"))
    if ours != ["integrity-humanx", "integrity-llm-bus"]:
        raise SystemExit(f"expected integrity-humanx and integrity-llm-bus alone, found {ours}")
    results = {}

    # --- the bus hub, with the room enabled ---------------------------------------------------
    keys = {name: secrets.token_urlsafe(32) for name in ("web", "vendor")}
    digest = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in keys.items()}
    room_ops = ["send", "poll", "get", "ack", "status", "room-arbiter", "room-arbiter-set", "vendor-cards", "status-batch"]
    principals = {"principals": {
        "humanx-web": {"key_sha256": digest["web"], "vendor": "humanx", "account": "example-a",
                       "addresses": [HUMAN], "ops": room_ops, "write": True, "rate_per_min": 600},
        "room-claude": {"key_sha256": digest["vendor"], "vendor": "claude", "account": "example-b",
                        "addresses": [ROOM_VENDOR], "ops": ["send", "poll", "get", "ack", "status"], "write": True,
                        "rate_per_min": 600},
    }, "accounts": {}}
    with tempfile.TemporaryDirectory() as work:
        principals_file = Path(work) / "principals.json"
        principals_file.write_text(json.dumps(principals), encoding="utf-8")
        os.chmod(principals_file, 0o644)
        hub, _ = tool(HUB_TOOL, "install", "--etc", str(HUB_ETC), "--state", str(HUB_STATE), "--runtime", str(HUB_RUNTIME),
                      "--bus-user", BUS, "--gateway-user", BUS_GATEWAY, "--socket-group", BUS_GROUP,
                      "--principals", str(principals_file))
    if hub["status"] != "installed":
        raise SystemExit(f"hub install: {hub}")
    # Enabling the room is the operator's step on the hub (HumanX does not write this file).
    room = {"human": HUMAN, "vendors": [ROOM_VENDOR],
            "arbiters": {"claude": {"address": ROOM_VENDOR, "ro": "invented check", "ro_verified": True}}}
    sudo("-u", BUS, PYTHON, "-I", "-c", "import sys; open(sys.argv[1], 'x', encoding='utf-8').write(sys.stdin.read())",
         str(HUB_STATE / "state" / "room.json"), stdin=json.dumps(room))
    hub_command = hub["start"]
    hub_environment = [f"{k}={v}" for k, v in hub_command["environment"].items()]
    daemon = subprocess.Popen(["sudo", "-n", "-u", hub_command["user"], "env", "-i", *hub_environment, *hub_command["argv"]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_for(daemon, lambda: sudo("test", "-S", str(HUB_RUNTIME / "core.sock"), expect=(0, 1)).returncode == 0,
             "the bus hub daemon")

    # --- HumanX install ------------------------------------------------------------------------
    install_args = ["--etc", str(ETC), "--state", str(STATE), "--runtime", str(RUNTIME), "--web-user", WEB,
                    "--gateway-user", GATEWAY, "--socket-group", GROUP, "--bus-group", BUS_GROUP,
                    "--bus-gateway-user", BUS_GATEWAY, "--bus-socket", str(HUB_RUNTIME / "core.sock"),
                    "--operator-id", OPERATOR, "--vendor", "claude", "--bind", HOST, "--port", str(PORT),
                    "--allow", HOST]
    with tempfile.TemporaryDirectory() as work:
        key_file = Path(work) / "web.key"
        key_file.write_text(keys["web"] + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
        report, _ = tool(TOOL, "install", *install_args, "--web-key", str(key_file))
        again, _ = tool(TOOL, "install", *install_args, "--web-key", str(key_file), expect=(2,))
    if report["status"] != "installed" or not all(exists("passwd", u) for u in (WEB, GATEWAY)) or not exists("group", GROUP):
        raise SystemExit(f"install: {report}")
    if "exists" not in again["error"]:
        raise SystemExit(f"a second install must refuse: {again}")
    results["second install"] = "refused: exists"
    doctor, _ = tool(TOOL, "doctor", "--etc", str(ETC))
    if doctor["status"] != "passed":
        raise SystemExit(f"doctor after install: {doctor}")
    results["doctor after install"] = "passed"

    with tempfile.TemporaryDirectory() as work:
        snapshot = Path(work) / "seed.sqlite3"
        events = synthetic_snapshot(snapshot)
        sudo("install", "-o", "root", "-g", GATEWAY, "-m", "0440", str(snapshot),
             str(STATE / "gateway" / "integrity" / "seed.sqlite3"))

    sudo("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--groups", BUS_GROUP, VENDOR_SIDE)
    sudo("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", OUTSIDER)
    gateway = start(report, "gateway")
    wait_for(gateway, lambda: sudo("test", "-S", str(RUNTIME / "gw.sock"), expect=(0, 1)).returncode == 0,
             "the read-only gateway")
    web = start(report, "web")
    wait_for(web, port_open, "the web")
    doctor, _ = tool(TOOL, "doctor", "--etc", str(ETC))
    if doctor["status"] != "passed" or not any(c["check"] == "gateway socket" and c["ok"] for c in doctor["checks"]):
        raise SystemExit(f"doctor while running: {doctor}")
    results["doctor while running"] = "passed, gateway socket owner and mode checked"

    # --- the read-only gateway: who may ask, decided by SO_PEERCRED ----------------------------
    sock = RUNTIME / "gw.sock"
    answer = ask(BUS_GATEWAY, sock, {"vendor": "claude", "op": "integrity", "args": {"q": "stats"}})
    if answer.get("ok") is not True or answer.get("events") != events:
        raise SystemExit(f"gateway integrity stats: {answer}")
    answer = ask(BUS_GATEWAY, sock, {"vendor": "claude", "op": "integrity", "args": {"q": "recent", "n": 2}})
    if answer.get("ok") is not True or [e["id"] for e in answer["events"]] != [3, 2]:
        raise SystemExit(f"gateway integrity recent: {answer}")
    results["bus gateway account reads the snapshot"] = f"ok, {events} synthetic events"
    for case, user, request, text in (
        ("vendor outside the room", BUS_GATEWAY, {"vendor": "grok", "op": "integrity", "args": {"q": "stats"}},
         "read gateways are only for the HumanX room Arbiters"),
        ("web account asks as a vendor", WEB, {"vendor": "claude", "op": "integrity", "args": {"q": "stats"}},
         "only the bus gateway may call"),
        ("web account asks for the ring screen while it is off", WEB,
         {"vendor": "web-rings", "op": "switch",
          "args": {"ip": "192.0.2.1", "cmds": ["show ports description", "show stp ports", "show stp", "show erps"]}},
         "only the bus gateway may call"),
        ("another account in the socket group", GATEWAY, {"vendor": "claude", "op": "integrity", "args": {"q": "stats"}},
         "only the bus gateway may call"),
        ("SQL that is not a read", BUS_GATEWAY, {"vendor": "claude", "op": "sql", "args": {"query": "DROP TABLE example"}},
         "Отказ шлюза"),
        ("switch outside the configured networks", BUS_GATEWAY,
         {"vendor": "claude", "op": "switch", "args": {"ip": "192.0.2.1", "cmds": ["show switch"]}},
         "не из сети управления"),
    ):
        expect_error(ask(user, sock, request), text, case)
        results[f"gateway: {case}"] = f"refused: {text}"
    for user in (OUTSIDER, BUS):
        answer = ask(user, sock, {"vendor": "claude", "op": "integrity", "args": {"q": "stats"}})
        if answer.get("connect_error") != "PermissionError":
            raise SystemExit(f"{user} is outside the gateway socket group and must not connect: {answer}")
    results["gateway: accounts outside the socket group"] = "connect refused: PermissionError"
    log = sudo("cat", str(STATE / "gateway" / "gw.jsonl")).stdout.splitlines()
    if len(log) != 8 or "DROP" in "\n".join(log) or not all(json.loads(line).get("req_sha256") for line in log):
        raise SystemExit(f"gateway log: expected 8 records with request hashes and no request text, got {len(log)}")
    results["gateway log"] = "8 records, request sha256 only"

    # --- the web on loopback ------------------------------------------------------------------
    status, headers, page = http_call("GET", "/")
    text = page.decode("utf-8")
    if status != 200 or "Комната оператора" not in text or keys["web"] in text or headers.get("X-Frame-Options") != "DENY":
        raise SystemExit(f"GET /: HTTP {status}")
    build = re.search(r"const BUILD='([^']+)'", text).group(1)
    results["web: page"] = "200, no key in the page, X-Frame-Options DENY"
    for case, call, expected in (
        ("page from an address outside the allow list", ("GET", "/", None, None, "127.0.0.2"), 403),
        ("send from an address outside the allow list", ("POST", "/api/send", {"body": "x", "page": build},
                                                         {"X-HumanX": "1"}, "127.0.0.2"), 403),
        ("send without the X-HumanX header", ("POST", "/api/send", {"body": "x", "page": build}, None, None), 403),
        ("ring screen while it is not configured", ("GET", "/rings", None, None, None), 404),
    ):
        status, _headers, _payload = http_call(*call)
        if status != expected:
            raise SystemExit(f"web: {case}: HTTP {status}, expected {expected}")
        results[f"web: {case}"] = f"HTTP {status}"
    state = http_json("GET", "/api/state")
    if state["arbiter"] is not None or [c["vendor"] for c in state["cards"]] != ["claude"]:
        raise SystemExit(f"web state before an Arbiter is chosen: arbiter={state['arbiter']} cards={state['cards']}")
    results["web: state"] = "200, no Arbiter yet, one vendor card"
    header = {"X-HumanX": "1"}
    answer = http_json("POST", "/api/send", {"body": "invented question", "page": build}, header)
    if answer.get("ok") or "Арбитра" not in str(answer.get("error")):
        raise SystemExit(f"send before an Arbiter is chosen must refuse: {answer}")
    answer = http_json("POST", "/api/arbiter", {"vendor": "claude"}, header)
    if answer.get("ok") is not True:
        raise SystemExit(f"choose the Arbiter: {answer}")
    question = "invented question " + uuid.uuid4().hex[:8]
    answer = http_json("POST", "/api/send", {"body": question, "page": build}, header)
    if answer.get("ok") is not True:
        raise SystemExit(f"send: {answer}")

    # --- the vendor side reads the question from the bus and answers ---------------------------
    hub_sock = HUB_RUNTIME / "core.sock"
    queue = ask(VENDOR_SIDE, hub_sock, {"v": 1, "op": "poll", "token": keys["vendor"], "args": {}})
    if queue.get("ok") is not True:
        raise SystemExit(f"vendor poll: {queue}")
    found = None
    for item in queue["result"]["queue"]:
        message = ask(VENDOR_SIDE, hub_sock, {"v": 1, "op": "get", "token": keys["vendor"], "args": {"id": item["id"]}})
        if message.get("ok") and message["result"]["message"]["body"] == question:
            found = message["result"]["message"]
    if not found or found["from"] != HUMAN:
        raise SystemExit("the question did not reach the room vendor from the operator address")
    reply = "invented answer " + uuid.uuid4().hex[:8]
    answer = ask(VENDOR_SIDE, hub_sock, {"v": 1, "op": "send", "token": keys["vendor"],
                                         "args": {"to": HUMAN, "id": uuid.uuid4().hex[:16], "body": reply,
                                                  "reply_to": found["id"]}})
    if answer.get("ok") is not True:
        raise SystemExit(f"vendor reply: {answer}")
    ask(VENDOR_SIDE, hub_sock, {"v": 1, "op": "ack", "token": keys["vendor"], "args": {"id": found["id"]}})
    state = http_json("GET", "/api/state")
    mine = [m for m in state["chat"] if m["side"] == "me" and m["body"] == question]
    theirs = [m for m in state["chat"] if m["side"] == "arb" and m["body"] == reply]
    if not mine or mine[0]["status"] != "answered" or not theirs or theirs[0]["who"] != ROOM_VENDOR:
        raise SystemExit("the web did not show the vendor's answer under the question")
    results["web → bus → vendor → bus → web"] = "question delivered from human-ci, answer shown, status answered"

    # --- removal ------------------------------------------------------------------------------
    refused, _ = tool(TOOL, "uninstall", "--etc", str(ETC), "--yes", expect=(3,))
    kept = sudo("test", "-d", str(STATE), expect=(0, 1)).returncode == 0 and exists("passwd", WEB)
    if refused["status"] != "refused" or not kept:
        raise SystemExit(f"uninstall while the web and the gateway run must refuse and keep everything: {refused}")
    results["uninstall while the web and the gateway run"] = "refused, nothing removed"
    stop(WEB, web)
    stop(GATEWAY, gateway)
    sudo("install", "-o", "root", "-g", "root", "-m", "0600", "/dev/null", str(ETC / "my.cnf"))
    doctor, _ = tool(TOOL, "doctor", "--etc", str(ETC))
    refused, _ = tool(TOOL, "uninstall", "--etc", str(ETC), "--yes", expect=(3,))
    if doctor["status"] != "passed" or refused["status"] != "refused" or "my.cnf" not in refused["reason"]:
        raise SystemExit(f"an owner file: doctor {doctor['status']}, uninstall {refused}")
    results["uninstall with an owner file in the configuration folder"] = "refused, the file is named"
    sudo("rm", "--", str(ETC / "my.cnf"))
    dry, _ = tool(TOOL, "uninstall", "--etc", str(ETC))
    if dry["status"] != "dry-run" or sudo("test", "-d", str(STATE), expect=(0, 1)).returncode != 0:
        raise SystemExit(f"uninstall without --yes must remove nothing: {dry}")
    removed, _ = tool(TOOL, "uninstall", "--etc", str(ETC), "--yes")
    doctor, _ = tool(TOOL, "doctor", "--etc", str(ETC), expect=(3,))
    left = [p for p in (ETC, STATE, RUNTIME) if sudo("test", "-e", str(p), expect=(0, 1)).returncode == 0]
    accounts = [n for n in (WEB, GATEWAY) if exists("passwd", n)] + [n for n in (GROUP, WEB, GATEWAY) if exists("group", n)]
    member = GROUP in run(["id", "-nG", BUS_GATEWAY]).stdout.split()
    if removed["status"] != "removed" or doctor["status"] != "not-installed" or left or accounts or member:
        raise SystemExit(f"after uninstall: {removed} {doctor} left={left} accounts={accounts} member={member}")
    results["uninstall"] = "removed; doctor: not-installed; no accounts, groups or folders left"
    hub_doctor, _ = tool(HUB_TOOL, "doctor", "--etc", str(HUB_ETC))
    if hub_doctor["status"] != "passed":
        raise SystemExit(f"the bus hub after HumanX was removed: {hub_doctor}")
    results["bus hub doctor after HumanX was removed"] = "passed"

    stop(BUS, daemon)
    for user in (VENDOR_SIDE, OUTSIDER):
        sudo("userdel", user)
    tool(HUB_TOOL, "uninstall", "--etc", str(HUB_ETC), "--yes")
    tool(HUB_TOOL, "doctor", "--etc", str(HUB_ETC), expect=(3,))
    sudo(PYTHON, "-m", "pip", "uninstall", "--quiet", "--yes", "integrity-humanx", "integrity-llm-bus")
    if Path(TOOL).exists() or Path(HUB_TOOL).exists():
        raise SystemExit("pip uninstall left a command behind")
    sudo("rm", "-rf", "--", str(VENV))
    print(json.dumps({"passed": True, "checks": results}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
