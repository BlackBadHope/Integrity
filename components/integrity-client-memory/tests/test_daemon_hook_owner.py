"""Codex app-server daemon hooks run without CODEX_THREAD_ID.

Codex 0.166 started from its app-server daemon gives hooks (and the brokers
they spawn) only CODEX_MANAGED_* variables. Under profile-selected Linux user
custody the live pinned vendor ancestor proves the caller; the subject still
comes from the Native hook payload or the hook-issued private claim, never
from the model. Every other mode keeps the strict environment equality.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


SOURCE = (Path(__file__).resolve().parents[1]
          / "src/integrity_client_memory/resources/windows/integrity_client_turn_envelope.py")
FUNCTIONS = {
    "_sha256_bytes", "_sha256_text", "_identity_hash", "_linux_user_custody_proven",
    "_native_caller_identity", "consume_owning_lifecycle", "revalidate_consumed_own_lifecycle",
}
THREAD = "11111111-1111-4111-8111-111111111111"
OTHER = "33333333-3333-4333-8333-333333333333"
TURN = "22222222-2222-4222-8222-222222222222"
LIFECYCLE = "lifecycle:" + "c" * 43


class FixtureEnvelopeError(RuntimeError):
    pass


def load(environ, *, proven=True, name="posix"):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert {node.name for node in selected} == FUNCTIONS
    namespace: dict[str, Any] = dict(Any=Any, hashlib=hashlib, json=json, math=math, re=re,
                                     TurnEnvelopeError=FixtureEnvelopeError,
                                     os=SimpleNamespace(name=name, environ=dict(environ)))
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), "exec"), namespace)
    if proven is not None:
        namespace["_linux_user_custody_proven"] = lambda: proven
    return namespace


@pytest.mark.parametrize("environ,proven,expected,result", [
    ({"CODEX_THREAD_ID": THREAD}, False, THREAD, THREAD),   # Windows / system custody
    ({"CODEX_THREAD_ID": THREAD}, False, None, THREAD),
    ({}, True, THREAD, THREAD),                            # daemon hook, pinned ancestor
])
def test_caller_identity_accepts_native_or_proven_user_custody(environ, proven, expected, result):
    assert load(environ, proven=proven)["_native_caller_identity"](expected) == result


@pytest.mark.parametrize("environ,proven,expected", [
    ({"CODEX_THREAD_ID": OTHER}, True, THREAD),   # a present value never yields to custody
    ({}, False, THREAD),                          # no env and no pinned ancestor
    ({}, True, None),                             # no non-model subject to stand in
    ({"CODEX_THREAD_ID": ""}, True, THREAD),
])
def test_caller_identity_refuses_conflict_or_unproven_absence(environ, proven, expected):
    with pytest.raises(FixtureEnvelopeError, match="caller mismatch"):
        load(environ, proven=proven)["_native_caller_identity"](expected)


@pytest.mark.parametrize("name,answer,result", [
    ("posix", True, True), ("posix", False, False), ("posix", "yes", False), ("nt", True, False),
])
def test_envelope_delegates_custody_proof_to_owning_native(monkeypatch, name, answer, result):
    owning = ModuleType("integrity_client_memory.owning_native")
    owning.user_custody_caller_proven = lambda: answer
    package = ModuleType("integrity_client_memory")
    package.owning_native = owning
    monkeypatch.setitem(sys.modules, "integrity_client_memory", package)
    monkeypatch.setitem(sys.modules, "integrity_client_memory.owning_native", owning)
    assert load({}, proven=None, name=name)["_linux_user_custody_proven"]() is result


@pytest.mark.parametrize("name,mode,ancestor,result", [
    ("posix", "user", True, True),
    ("posix", "user", False, False),
    ("posix", "system", True, False),
    ("nt", "user", True, False),
])
def test_user_custody_proof_requires_posix_user_mode_and_pinned_ancestor(
        monkeypatch, name, mode, ancestor, result):
    from integrity_client_memory import linux_user_native, owning_native
    calls = []

    def find_vendor_ancestor(executable, sha256):
        calls.append((executable, sha256))
        if not ancestor:
            raise linux_user_native.LinuxNativeError("linux_native_vendor_ancestor_missing")
        return 4242, "birth"

    monkeypatch.setattr(owning_native.os, "name", name)
    monkeypatch.setattr(owning_native, "custody_mode", lambda: mode)
    monkeypatch.setattr(owning_native, "_integrity_value",
                        {"linux_native_executable": "/pinned/codex",
                         "linux_native_executable_sha256": "e" * 64}.__getitem__)
    monkeypatch.setattr(linux_user_native, "find_vendor_ancestor", find_vendor_ancestor)
    assert owning_native.user_custody_caller_proven() is result
    assert calls == ([("/pinned/codex", "e" * 64)] if (name, mode) == ("posix", "user") else [])


class Handoff:
    def __init__(self, tmp_path, environ, *, proven=True, claim_thread=THREAD):
        self.ns = load(environ, proven=proven)
        self.root = tmp_path
        (tmp_path / "owning-lifecycle").mkdir()
        self.state = {"turn_id": TURN, "turn_memory_generation": 3,
                      "turn_memory_intent_id": "intent:" + "a" * 64, "prompt_sha256": "d" * 64,
                      "model_mcp_context_admission_id": "fixture-admission"}
        self.revision = "fixture-revision"
        self.sources = []
        self.ns.update(
            time=SimpleNamespace(time=lambda: 100.0),
            _ensure_root=lambda _root=None: self.root,
            _exclusive_root_lock=self.exclusive,
            _read=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _unprotect=lambda _encoding, payload, _entropy: payload.encode(),
            _current_owning_source=self.source,
            _owning_process_ancestor=lambda _pid, _birth: True,
            _native_owning_head=lambda identity: {"id": TURN, "status": "inProgress"},
        )
        self.arguments = {"registration_id": "fixture-registration", "outcome": "no-event",
                          "no_event_reason": "read-only"}
        claims = {
            "protocol": "integrity/owning-hook-lifecycle/v1", "name": "integrity_turn_memory_close",
            "arguments_sha256": self.ns["_sha256_text"](
                json.dumps(self.arguments, sort_keys=True, separators=(",", ":"))),
            "expires_epoch": 200.0, "mode": "current", "source_revision_sha256": self.revision,
            "thread_id_sha256": self.ns["_identity_hash"](THREAD, "thread_id"),
            "turn_id_sha256": self.ns["_identity_hash"](TURN, "turn_id"), "generation": 3,
            "intent_id": self.state["turn_memory_intent_id"],
            "prompt_sha256": self.state["prompt_sha256"],
            "context_admission_id": self.state["model_mcp_context_admission_id"],
            "issuer_parent_pid": 123, "issuer_parent_birth": "fixture-birth",
        }
        if claim_thread is not None:
            claims["thread_id"] = claim_thread
        self.claims = claims
        path = tmp_path / "owning-lifecycle" / (self.ns["_sha256_text"](LIFECYCLE) + ".json")
        path.write_text(json.dumps({"encoding": "fixture", "payload_b64": json.dumps(claims)}),
                        encoding="utf-8")
        self.path = path

    @contextmanager
    def exclusive(self, _root):
        yield

    def source(self, identity, **_kw):
        # The real reader re-checks the caller first; keep that ordering here.
        self.ns["_native_caller_identity"](identity)
        self.sources.append(identity)
        return deepcopy(self.state), self.revision

    def consume(self):
        return self.ns["consume_owning_lifecycle"](LIFECYCLE, "integrity_turn_memory_close",
                                                  self.arguments, root=self.root)


def test_daemon_broker_consumes_hook_claim_under_proven_user_custody(tmp_path):
    handoff = Handoff(tmp_path, {})
    assert handoff.consume() == handoff.claims
    assert handoff.sources and set(handoff.sources) == {THREAD}
    assert not handoff.path.exists()


def test_daemon_broker_refuses_without_pinned_ancestor(tmp_path):
    handoff = Handoff(tmp_path, {}, proven=False)
    with pytest.raises(FixtureEnvelopeError, match="caller mismatch"):
        handoff.consume()
    assert not handoff.path.exists(), "a refused handoff stays consumed"


def test_claim_thread_must_match_its_own_commitment(tmp_path):
    handoff = Handoff(tmp_path, {}, claim_thread=OTHER)
    with pytest.raises(FixtureEnvelopeError, match="superseded"):
        handoff.consume()


def test_present_environment_conflicting_with_claim_is_refused(tmp_path):
    handoff = Handoff(tmp_path, {"CODEX_THREAD_ID": OTHER})
    with pytest.raises(FixtureEnvelopeError, match="caller mismatch"):
        handoff.consume()


def test_legacy_claim_without_thread_keeps_strict_environment(tmp_path):
    native, absent = tmp_path / "native", tmp_path / "absent"
    native.mkdir()
    absent.mkdir()
    handoff = Handoff(native, {"CODEX_THREAD_ID": THREAD}, proven=False, claim_thread=None)
    assert handoff.consume() == handoff.claims
    handoff = Handoff(absent, {}, claim_thread=None)
    with pytest.raises(FixtureEnvelopeError, match="caller mismatch"):
        handoff.consume()


BROKER = SOURCE.with_name("integrity-client-turn-broker.py")


@pytest.mark.parametrize("source", [BROKER, SOURCE.with_name("admission.py")])
def test_presentation_artifact_publishes_without_hard_links(tmp_path, monkeypatch, source):
    """Android app sandboxes deny link(); DroidDeck reported a PermissionError fault."""
    text = None
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and "def store_file(root, data)" in node.value):
            text = node.value
    assert text is not None
    module = ModuleType("fixture_compact_admission")
    configuration = ModuleType("integrity_client_memory.configuration")
    configuration.value = lambda _name: ""
    configuration.require_config = lambda: None
    monkeypatch.setitem(sys.modules, "integrity_client_memory.configuration", configuration)
    exec(compile(text, str(source), "exec"), module.__dict__)

    def denied(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(module.os, "link", denied)
    data = b'{"fixture":true}'
    reference = module.store_file(tmp_path / "artifacts", data)
    assert reference["sha256"] == hashlib.sha256(data).hexdigest()
    assert (tmp_path / "artifacts" / (reference["sha256"] + ".json")).read_bytes() == data
    assert not list((tmp_path / "artifacts").glob(".admission-*"))
    assert module.store_file(tmp_path / "artifacts", data) == reference
