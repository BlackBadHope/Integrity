"""Disposable Memory stand on a private Unix socket; one real facade per connection.

Keys are RAM-only and the producer is the real Linux Codex Native hook under a
test vendor process. Arguments: root, socket, info-file, repository[, flags].
"""
import json
import os
from pathlib import Path
import socket
import sys
import threading

import pytest

REPO = Path(sys.argv[4]).resolve()
sys.path.insert(0, str(REPO / "tests"))
from recovery_stand_fixture import Stand  # noqa: E402
from integrity_guardian import memory_synapse_mcp as mcp  # noqa: E402
from integrity_guardian.memory_synapse_mcp_protocol import dispatch  # noqa: E402

root, sock_path, info_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
patch = pytest.MonkeyPatch()
root.mkdir(mode=0o700)
stand = Stand(root, patch)
if "--capacity-exhausted" in sys.argv[5:]:
    filler = stand.facade()
    stand.initialize(filler)
    assert stand.fill_reservations(filler) > 0
lts = mcp.MemorySynapseLtsService(stand.catalog.path)
info = {"namespace_fingerprint": stand.namespace, "seed_namespace": lts.snapshot()["source_namespace"]}
lock = threading.Lock()


def serve(connection):
    with connection, connection.makefile("rb") as reader, connection.makefile("wb") as writer:
        facade = stand.facade()
        for line in reader:
            try:
                request = json.loads(line)
            except ValueError:
                continue
            with lock:
                response = dispatch(facade, request)
            if response is not None:
                writer.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
                writer.flush()


server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
previous = os.umask(0o077)
server.bind(str(sock_path))
os.umask(previous)
server.listen(8)
info_path.write_text(json.dumps(info))
try:
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
finally:
    stand.stop()
    patch.undo()
