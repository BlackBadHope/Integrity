"""The canonical broker's transport-start gate on this platform, without configuration.

Only the StartupGate class is extracted from the shipped broker source and
executed with fixture constants; no broker, upstream or Native process starts.
"""
import ast
import errno
import os
from pathlib import Path
import secrets
import stat
import threading
import time

import pytest

BROKER = (Path(__file__).resolve().parents[1]
          / "src/integrity_client_memory/resources/windows/integrity-client-turn-broker.py")


class FixtureBrokerError(RuntimeError):
    def __init__(self, message, *, layer, request_sent=False, retryable=False):
        super().__init__(message)
        self.layer, self.request_sent, self.retryable = layer, request_sent, retryable


def gate_class(directory, wait=0.3):
    tree = ast.parse(BROKER.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "StartupGate")
    namespace = {"os": os, "time": time, "secrets": secrets, "errno": errno, "_gate_stat": stat,
                 "Path": Path, "BrokerError": FixtureBrokerError, "STARTUP_GATE_DIRECTORY": directory,
                 "STARTUP_GATE_SLOTS": 2, "STARTUP_GATE_WAIT_SECONDS": wait}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "startup-gate-fixture", "exec"), namespace)
    return namespace["StartupGate"]


def test_two_slots_bound_concurrent_starts_and_release_on_exit(tmp_path):
    Gate = gate_class(tmp_path / "gates")
    cancelled = threading.Event()
    first, second = Gate(cancelled), Gate(cancelled)
    with first, second:
        with pytest.raises(FixtureBrokerError, match="capacity wait expired"):
            with Gate(cancelled):
                pass
    with Gate(cancelled):
        pass


def test_cancelled_public_input_stops_waiting(tmp_path):
    Gate = gate_class(tmp_path / "gates", wait=5)
    cancelled = threading.Event()
    with Gate(cancelled), Gate(cancelled):
        cancelled.set()
        with pytest.raises(FixtureBrokerError, match="public input transport closed"):
            with Gate(cancelled):
                pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-only slot custody")
def test_posix_slots_are_owner_only_and_refuse_wider_or_linked_custody(tmp_path):
    directory = tmp_path / "gates"
    Gate = gate_class(directory)
    with Gate(threading.Event()):
        pass
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    slots = sorted(directory.iterdir())
    assert [p.name for p in slots] == ["slot-0.lock", "slot-1.lock"]
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in slots)
    directory.chmod(0o750)
    with pytest.raises(OSError, match="custody invalid"):
        with Gate(threading.Event()):
            pass
    directory.chmod(0o700)
    slots[0].unlink()
    slots[0].symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        with Gate(threading.Event()):
            pass
