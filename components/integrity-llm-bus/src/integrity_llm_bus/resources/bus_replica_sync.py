# SPDX-License-Identifier: BUSL-1.1
"""bus_replica_sync - keeps the client's read-only replica (state/bus.sqlite3) in step with the hub.

Runs only when state/CORE.json exists. Started by the client watchdog; stop flag state/REPLICA_STOP.
  * watch stream (bus event metadata, no bodies): on an event it fetches changes after ~0.3 s;
  * every 60 s a control `changes` call even without events (TTL deletions emit no events);
  * heartbeat in state/replica-sync.json: cursor, last sync time, stream state, last error.
Executes nothing itself: it only reads bus replies (JSON) and applies rows to the replica.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bus_remote as R  # noqa: E402

STATE = Path(os.environ.get("BUS_STATE_DIR") or _integrity_value('state_directory'))
BEAT = STATE / "replica-sync.json"
STOP = STATE / "REPLICA_STOP"
_wake = threading.Event()
_info = {"stream": "init", "last_error": None, "pulls": 0}


def beat():
    try:
        doc = {"ts": int(time.time()), "pid": os.getpid(), "cursor": R.cursor(STATE / "bus.sqlite3"), **_info}
        tmp = BEAT.with_suffix(".tmp"); tmp.write_text(json.dumps(doc), encoding="utf-8"); os.replace(tmp, BEAT)
    except (OSError, ValueError):
        pass


def watcher():
    """watch stream over ssh. Any event (message/ack/registry/wake) wakes the synchronisation."""
    while not STOP.exists():
        c = R.conf(STATE)
        ssh = R.ssh_bin(c)
        argv = [ssh, *c.get("ssh_args", []), "-o", "BatchMode=yes", "-o", f"ConnectTimeout={c.get('connect_timeout', 8)}",
                "-o", "ServerAliveInterval=20", "-o", "IdentitiesOnly=yes", "-i", c["keys"]["hub"], c["dest"], "watch"]
        try:
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env=R.ssh_env(ssh), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            p.stdin.write(b"{}"); p.stdin.close()
            _info["stream"] = "connecting"
            for line in p.stdout:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("event") == "hello":
                    _info["stream"] = "up"; _wake.set()
                elif ev.get("event") not in ("hb", None):
                    _wake.set()
                if STOP.exists():
                    p.kill(); return
            p.wait(timeout=5)
        except Exception as exc:  # network, ssh or hub unavailable: reconnect
            _info["last_error"] = f"watch: {type(exc).__name__}: {str(exc)[:120]}"
        _info["stream"] = "down"; _wake.set()
        time.sleep(5)


def main():
    if not R.active(STATE):
        print("no state/CORE.json: bus is not moved to core; nothing to do"); return 0
    threading.Thread(target=watcher, daemon=True).start()
    last = 0.0
    while not STOP.exists():
        fired = _wake.wait(timeout=60)
        _wake.clear()
        if fired:
            time.sleep(0.3)   # coalesce a burst of events
            _wake.clear()
        try:
            R.pull(STATE); _info["pulls"] += 1; _info["synced_at"] = int(time.time()); _info["last_error"] = None
        except Exception as exc:
            _info["last_error"] = f"pull: {type(exc).__name__}: {str(exc)[:160]}"
            time.sleep(5)
        if time.time() - last > 15 or fired:
            beat(); last = time.time()
    _info["stream"] = "stopped"; beat()
    return 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
