"""Shared setup for the bus script tests (tests/live) and the hub tests (tests/core).

The scripts in ``resources/`` import each other by plain module name and read
their state directory from the owner configuration. This conftest writes a
synthetic, fully configured file into a temporary directory outside the
source tree, points ``INTEGRITY_LLM_BUS_CONFIG`` at it and puts the resource
directory on ``sys.path``. No value refers to a real host, account or network.
"""
from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

COMPONENT = Path(__file__).resolve().parents[1]
RESOURCES = COMPONENT / "src" / "integrity_llm_bus" / "resources"
CORE = RESOURCES / "core"

_ROOT = Path(tempfile.mkdtemp(prefix="integrity-llm-bus-tests-"))
atexit.register(shutil.rmtree, _ROOT, True)
STATE = _ROOT / "configured-state"
STATE.mkdir()
VALUES = {
    "state_directory": str(STATE),
    "path_d4f3db5417f4": str(_ROOT / "file-bus"),
    "path_dd2435d503a6": str(_ROOT),
    "endpoint_173b0c3b2ac1": "https://webhook.example.invalid/hook/",
    "native_peer_port_49481": "49481",
    "native_peer_host_id": "node-a",
    "chatgpt_thread_id": "00000000-0000-4000-8000-0000000000c1",
    "core_config": str(_ROOT / "core.json"),
    "routes_seed": str(_ROOT / "seed.sqlite3"),
    "routes_module": str(_ROOT / "uroboros_routes.py"),
    "routes_catalog": str(_ROOT / "catalog.json"),
    "routes_source_label": "seed://example/project",
}
document = json.loads((COMPONENT / "configuration.example.json").read_text(encoding="utf-8"))
document.update(configured=True, values=VALUES)
CONFIG = _ROOT / "configuration.json"
CONFIG.write_text(json.dumps(document), encoding="utf-8")
os.environ["INTEGRITY_LLM_BUS_CONFIG"] = str(CONFIG)
for path in (str(CORE), str(RESOURCES)):
    if path not in sys.path:
        sys.path.insert(0, path)

