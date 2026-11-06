"""Option 4: the model's broker opens the turn registration right after admission.

The broker sends the open over its admitted warm stream, with the same dispatch
journal as every owning lifecycle call, and leaves a one-use hand-off for the
owning hook. The hook accepts it only for its exact turn and arguments, and
otherwise opens the registration itself.
"""
import ast
import hashlib
import json
import os
import re
from pathlib import Path

import pytest

RESOURCES = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources"
BROKERS = {"windows": "windows/integrity-client-turn-broker.py", "linux": "linux/integrity-client-turn-broker.py"}
HOOKS = {"windows": "windows/native/integrity-client-admission.py", "linux": "linux/admission.py"}
BROKER_METHODS = ("_registration_receipt", "_open_own_registration_after_admission", "_validate_current_open",
                  "_begin_lifecycle_dispatch", "_lifecycle_request_key", "_remember_uncertain_lifecycle",
                  "_standalone_turn_memory_call", "_check_own_lifecycle", "_ack_pending_context_replays",
                  "_observe_late_append", "_observe_late_lifecycle", "_observe_current_lifecycle",
                  "_lifecycle_terminal", "_read_existing_lifecycle")
THREAD = "0f6d1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
TURN = "11111111-2222-4333-8444-555555555555"
MACHINE = "machine:unit-host"
DIGEST = "sha256:" + "a" * 64
PROMPT = "b" * 64
ADMISSION = "sha256:" + "c" * 64
sha = lambda value: hashlib.sha256(value.encode()).hexdigest()  # noqa: E731
CONSENT = {"protocol": "integrity-client/broker-turn-registration-handoff/v1", "intent_id": "intent:" + DIGEST[7:]}


class BrokerError(RuntimeError):
    def __init__(self, message, *, layer="broker", request_sent=False, retryable=True):
        super().__init__(message)
        self.layer, self.request_sent, self.retryable = layer, request_sent, retryable


class TurnEnvelopeError(ValueError):
    pass


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def signed_receipt(arguments):
    receipt = {"protocol": "integrity-guardian/turn-memory-registration/v1",
               "identity": {k: arguments[k] for k in ("machine_id", "thread_id", "turn_id", "intent_id")},
               "prompt_sha256": arguments["prompt_sha256"], "terminal_required": True,
               "production_authority": False, "namespace_fingerprint": "sha256:" + "d" * 64,
               "signature": {"algorithm": "ed25519", "value": "sig"}}
    unsigned = {k: v for k, v in receipt.items() if k not in {"signature", "receipt_id"}}
    raw = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    receipt["receipt_id"] = "sha256:" + hashlib.sha256(b"turn-memory-registration-v1\0" + raw).hexdigest()
    return receipt


def open_arguments():
    return {"machine_id": MACHINE, "thread_id": THREAD, "turn_id": TURN,
            "intent_id": "intent:" + DIGEST[7:], "prompt_sha256": PROMPT}


class Upstream:
    def __init__(self, respond):
        self.respond, self.calls, self._next_id = respond, [], 7
        self._late_lifecycle_requests = {}
        self.process = None

    def call_tool(self, name, arguments):
        # Canonical readback of an earlier dispatch (linux) finds nothing here.
        self.calls.append(("readback", {"name": name, "arguments": arguments}, None))
        return {"isError": True, "content": []}

    def request(self, method, params, timeout=None):
        self.calls.append((method, params, timeout))
        self._next_id += 1
        return self.respond(params)


def broker_class(family, tmp_path, monkeypatch, *, head_status="inProgress"):
    source = (RESOURCES / BROKERS[family]).read_text(encoding="utf-8")
    tree = ast.parse(source)
    broker = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TurnBroker")
    body = [n for n in broker.body if isinstance(n, ast.FunctionDef) and n.name in BROKER_METHODS]
    body += [n for n in broker.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id in {"POST_ADMISSION_OPEN_TIMEOUT_SECONDS",
                                                          "TURN_REGISTRATION_HANDOFF_PROTOCOL"} for t in n.targets)]
    assert {n.name for n in body if isinstance(n, ast.FunctionDef)} >= set(BROKER_METHODS) - {"_read_existing_lifecycle"}
    module = ast.fix_missing_locations(ast.Module(
        body=[ast.ClassDef(name="Broker", bases=[], keywords=[], body=body, decorator_list=[], type_params=[])],
        type_ignores=[]))

    def write_atomic(path, value, *, create_only=False):
        path.write_text(json.dumps(value), encoding="utf-8")

    envelope = type("Envelope", (), {
        "TurnEnvelopeError": TurnEnvelopeError, "_RESUME_CLAIM_OWNER": (THREAD, 3, DIGEST),
        "_machine_id": staticmethod(lambda: MACHINE), "_write_atomic": staticmethod(write_atomic),
        "_native_owning_head": staticmethod(lambda thread: {"id": TURN, "status": head_status}),
    })
    namespace = {"json": json, "hashlib": hashlib, "os": os, "re": re, "Path": Path, "BrokerError": BrokerError,
                 "turn_envelope": envelope, "_json_bytes": _json_bytes, "Any": object, "UpstreamFacade": object}
    exec(compile(module, BROKERS[family], "exec"), namespace)
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path))
    return namespace["Broker"], envelope


def admitted_broker(family, tmp_path, monkeypatch, respond, *, state_extra=None, **kwargs):
    cls, envelope = broker_class(family, tmp_path, monkeypatch, **kwargs)
    broker = cls()
    broker._owning_hook_lifecycle_ref = None
    broker._pending_context_replay_acks = []
    broker._context_replay_acks_awaiting_public_delivery = set()
    broker._pending_append_arguments = None
    broker.bound = True
    broker.upstream = Upstream(respond)
    broker._own_turn_binding = {
        "hashes": {"machine_id": sha(MACHINE), "thread_id": sha(THREAD), "turn_id": sha(TURN)},
        "intent_id": "intent:" + DIGEST[7:], "prompt_sha256": PROMPT, "generation": 3,
        "admitted": True, "turn_ref_digest": DIGEST, "context_admission_id": ADMISSION,
        "project_scope_sha256": None}
    state = {"turn_id": TURN, "turn_memory_generation": 3, "turn_memory_intent_id": "intent:" + DIGEST[7:],
             "prompt_sha256": PROMPT, "turn_memory_status": "provisional",
             "turn_memory_registration_handoff": CONSENT, **(state_extra or {})}
    (tmp_path / (sha(THREAD) + ".json")).write_text(json.dumps(state), encoding="utf-8")
    return broker, envelope


def handoff_path(tmp_path):
    return tmp_path / ("turn-registration-handoff-" + sha(THREAD) + ".json")


def ok(params):
    return {"content": [{"type": "text", "text": json.dumps({"receipt": signed_receipt(params["arguments"])})}]}


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_broker_opens_over_warm_stream_and_hands_off_the_receipt(family, tmp_path, monkeypatch):
    broker, _ = admitted_broker(family, tmp_path, monkeypatch, ok)
    broker._open_own_registration_after_admission()
    assert broker._post_admission_open_stage == "handed-off"
    [(method, params, timeout)] = [c for c in broker.upstream.calls if c[0] == "tools/call"]
    assert method == "tools/call" and params == {"name": "integrity_turn_memory_open", "arguments": open_arguments()}
    assert timeout == broker.POST_ADMISSION_OPEN_TIMEOUT_SECONDS
    record = json.loads(handoff_path(tmp_path).read_text())
    assert record["arguments"] == open_arguments() and record["turn_ref_digest"] == DIGEST
    assert record["receipt"] == signed_receipt(open_arguments())
    # The same dispatch journal as every owning lifecycle call blocks a second open.
    assert len(list(tmp_path.glob("lifecycle-dispatch-*.json"))) == 1


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_dispatch_journal_prevents_a_second_open(family, tmp_path, monkeypatch):
    broker, _ = admitted_broker(family, tmp_path, monkeypatch, ok)
    broker._open_own_registration_after_admission()
    handoff_path(tmp_path).unlink()
    broker._open_own_registration_after_admission()
    sends = [call for call in broker.upstream.calls if call[0] == "tools/call"]
    assert len(sends) == 1 and not handoff_path(tmp_path).exists()
    assert broker._post_admission_open_stage == "skipped-broker-lifecycle-uncertain"


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_broker_rejects_a_receipt_for_other_arguments(family, tmp_path, monkeypatch):
    def foreign(params):
        other = {**params["arguments"], "turn_id": "99999999-2222-4333-8444-555555555555"}
        return {"content": [{"type": "text", "text": json.dumps({"receipt": signed_receipt(other)})}]}

    broker, _ = admitted_broker(family, tmp_path, monkeypatch, foreign)
    broker._open_own_registration_after_admission()
    assert broker._post_admission_open_stage == "receipt-invalid"
    assert not handoff_path(tmp_path).exists()


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_tampered_receipt_digest_is_rejected(family, tmp_path, monkeypatch):
    def tampered(params):
        receipt = signed_receipt(params["arguments"])
        receipt["prompt_sha256"] = "e" * 64
        return {"content": [{"type": "text", "text": json.dumps({"receipt": receipt})}]}

    broker, _ = admitted_broker(family, tmp_path, monkeypatch, tampered)
    broker._open_own_registration_after_admission()
    assert broker._post_admission_open_stage == "receipt-invalid"
    assert not handoff_path(tmp_path).exists()


@pytest.mark.parametrize("family", sorted(BROKERS))
@pytest.mark.parametrize("sent", [False, True])
def test_warm_failure_leaves_no_handoff(family, sent, tmp_path, monkeypatch):
    def broken(params):
        raise BrokerError("upstream closed", layer="broker-upstream", request_sent=sent)

    broker, _ = admitted_broker(family, tmp_path, monkeypatch, broken)
    broker._open_own_registration_after_admission()
    assert not handoff_path(tmp_path).exists()
    assert broker._post_admission_open_stage == ("send-outcome-unknown" if sent else "skipped-broker-upstream")
    # An unknown outcome is remembered; the journal keeps the hook from a second open.
    assert (broker._lifecycle_request_key("integrity_turn_memory_open", open_arguments())
            in getattr(broker, "_uncertain_lifecycle_requests", set())) is sent


@pytest.mark.parametrize("family", sorted(BROKERS))
@pytest.mark.parametrize("change", ["owner", "state", "head", "unbound", "no-consent", "other-intent"])
def test_broker_does_not_open_without_its_own_current_turn(family, change, tmp_path, monkeypatch):
    state_extra = {"state": {"turn_memory_registration_id": DIGEST},
                   # A hook that does not take the hand-off (or an older hook) never asked for it.
                   "no-consent": {"turn_memory_registration_handoff": None},
                   "other-intent": {"turn_memory_registration_handoff": {**CONSENT, "intent_id": "intent:" + "9" * 64}},
                   }.get(change)
    broker, envelope = admitted_broker(family, tmp_path, monkeypatch, ok, state_extra=state_extra,
                                       head_status="completed" if change == "head" else "inProgress")
    if change == "owner":
        envelope._RESUME_CLAIM_OWNER = (THREAD, 4, DIGEST)
    if change == "unbound":
        broker._own_turn_binding["admitted"] = False
    broker._open_own_registration_after_admission()
    assert broker.upstream.calls == [] and not handoff_path(tmp_path).exists()
    assert broker._post_admission_open_stage.startswith("skipped-")


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_admission_already_recorded_by_the_hook_is_left_to_the_hook(family, tmp_path, monkeypatch):
    broker, _ = admitted_broker(family, tmp_path, monkeypatch, ok,
                                state_extra={"model_mcp_context_admission_id": ADMISSION})
    broker._open_own_registration_after_admission()
    assert broker.upstream.calls == []


@pytest.mark.parametrize("family", sorted(BROKERS))
def test_admission_response_is_not_changed(family):
    source = (RESOURCES / BROKERS[family]).read_text(encoding="utf-8")
    call = "self._open_own_registration_after_admission()"
    assert source.count(call) == 1
    block = source[source.index("self._adopt_admitted_own_binding(result)"):source.index(call)]
    assert "result" not in block.replace("self._adopt_admitted_own_binding(result)", "").replace(
        "self._save_delivered_context_resume(result)", "")
    method = source[source.index("    def _open_own_registration_after_admission"):]
    method = method[:method.index("\n    def ", 10)]
    assert "result[" not in method.replace("result = self.upstream.request", "")


# ---------------------------------------------------------------- hooks

class HookError(RuntimeError):
    pass


class HookTransportError(HookError):
    pass


def hook_namespace(family, tmp_path, lifecycle):
    source = (RESOURCES / HOOKS[family]).read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {"take_broker_registration_handoff", "open_admitted_turn_memory"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    body += [n for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "TURN_REGISTRATION_HANDOFF_PROTOCOL" for t in n.targets)]
    socket = type("Socket", (), {"gethostname": staticmethod(lambda: "unit-host")})
    namespace = {"json": json, "re": re, "hashlib": hashlib, "time": __import__("time"), "socket": socket, "Any": object,
                 "HookError": HookError, "HookTransportError": HookTransportError,
                 "state_root": lambda: tmp_path, "sha256_text": sha, "save_state": lambda identity, state: None,
                 "lifecycle_call": lifecycle, "remaining_lifecycle_seconds": lambda seconds: None,
                 "LIFECYCLE_BUDGET_SECONDS": 30, "LIFECYCLE_DEADLINE": None,
                 "_is_digest": lambda v: isinstance(v, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", v) is not None}
    exec(compile(ast.Module(body=body, type_ignores=[]), HOOKS[family], "exec"), namespace)
    return namespace


def hook_state():
    return {"turn_id": TURN, "turn_memory_intent_id": "intent:" + DIGEST[7:], "prompt_sha256": PROMPT,
            "turn_memory_generation": 3, "turn_ref_digest": DIGEST}


def write_handoff(tmp_path, **changes):
    record = {"protocol": "integrity-client/broker-turn-registration-handoff/v1", "turn_ref_digest": DIGEST,
              "generation": 3, "intent_id": "intent:" + DIGEST[7:], "arguments": open_arguments(),
              "receipt": signed_receipt(open_arguments()), **changes}
    handoff_path(tmp_path).write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize("family", sorted(HOOKS))
def test_hook_accepts_the_broker_receipt_without_a_cold_open(family, tmp_path):
    calls = []
    ns = hook_namespace(family, tmp_path, lambda *a, **k: calls.append(a) or {})
    write_handoff(tmp_path)
    receipt = ns["open_admitted_turn_memory"](THREAD, hook_state())
    assert receipt == signed_receipt(open_arguments()) and calls == []
    assert not handoff_path(tmp_path).exists()


@pytest.mark.parametrize("family", sorted(HOOKS))
@pytest.mark.parametrize("change", [{"turn_ref_digest": "sha256:" + "f" * 64}, {"generation": 2},
                                    {"arguments": {**open_arguments(), "turn_id": "99999999-2222-4333-8444-555555555555"}},
                                    {"protocol": "other"}])
def test_hook_ignores_a_foreign_or_stale_handoff_and_opens_itself(family, change, tmp_path):
    calls = []

    def lifecycle(name, arguments, **owning):
        calls.append((name, arguments, sorted(owning)))
        return {"receipt": signed_receipt(arguments)}

    ns = hook_namespace(family, tmp_path, lifecycle)
    write_handoff(tmp_path, **change)
    receipt = ns["open_admitted_turn_memory"](THREAD, hook_state())
    assert calls == [("integrity_turn_memory_open", open_arguments(), ["owning_identity", "owning_state"])]
    assert receipt == signed_receipt(open_arguments())
    assert not handoff_path(tmp_path).exists()


@pytest.mark.parametrize("family", sorted(HOOKS))
def test_hook_rejects_a_handoff_receipt_for_another_prompt(family, tmp_path):
    ns = hook_namespace(family, tmp_path, lambda *a, **k: {})
    other = {**open_arguments(), "prompt_sha256": "e" * 64}
    write_handoff(tmp_path, receipt=signed_receipt(other))
    with pytest.raises(HookError, match="turn_registration_invalid"):
        ns["open_admitted_turn_memory"](THREAD, hook_state())


@pytest.mark.parametrize("family", sorted(HOOKS))
def test_hook_without_handoff_opens_as_before(family, tmp_path):
    calls = []
    ns = hook_namespace(family, tmp_path, lambda name, arguments, **o: calls.append(name)
                        or {"receipt": signed_receipt(arguments)})
    assert ns["open_admitted_turn_memory"](THREAD, hook_state()) == signed_receipt(open_arguments())
    assert calls == ["integrity_turn_memory_open"]


# ---------------------------------------------------------------- Claude Native

NATIVE_BROKER = "claude-native/integrity-client-turn-broker.py"
NATIVE_HOOK = "claude-native/integrity-client-admission.py"


def native_broker(tmp_path, monkeypatch, respond, *, state_extra=None, head_status="inProgress"):
    source = (RESOURCES / NATIVE_BROKER).read_text(encoding="utf-8")
    broker = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == "TurnBroker")
    wanted = {"_registration_receipt", "_open_own_registration_after_admission", "_standalone_turn_memory_call",
              "_check_own_lifecycle", "_ack_pending_context_replays"}
    body = [n for n in broker.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    body += [n for n in broker.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id.endswith(("_TIMEOUT_SECONDS", "_PROTOCOL")) for t in n.targets)]
    module = ast.fix_missing_locations(ast.Module(
        body=[ast.ClassDef(name="Broker", bases=[], keywords=[], body=body, decorator_list=[], type_params=[])],
        type_ignores=[]))

    def write_atomic(path, value, *, create_only=False):
        path.write_text(json.dumps(value), encoding="utf-8")

    envelope = type("Envelope", (), {
        "TurnEnvelopeError": TurnEnvelopeError, "_machine_id": staticmethod(lambda: MACHINE),
        "_write_atomic": staticmethod(write_atomic),
        "_native_owning_head": staticmethod(lambda thread: {"id": TURN, "status": head_status})})
    namespace = {"json": json, "hashlib": hashlib, "os": os, "re": re, "Path": Path, "BrokerError": BrokerError,
                 "turn_envelope": envelope, "_integrity_value": lambda key: {"claude_session_id": THREAD}[key],
                 "Any": object, "UpstreamFacade": object}
    exec(compile(module, NATIVE_BROKER, "exec"), namespace)
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path))
    instance = namespace["Broker"]()
    instance._owning_hook_lifecycle_ref = None
    instance._pending_context_replay_acks = []
    instance._context_replay_acks_awaiting_public_delivery = set()
    instance.bound, instance.upstream = True, Upstream(respond)
    instance._own_turn_binding = {
        "hashes": {"machine_id": sha(MACHINE), "thread_id": sha(THREAD), "turn_id": sha(TURN)},
        "intent_id": "intent:" + DIGEST[7:], "prompt_sha256": PROMPT, "generation": 3, "admitted": True,
        "turn_ref_digest": DIGEST, "context_admission_id": ADMISSION}
    state = {"turn_id": TURN, "turn_memory_generation": 3, "turn_memory_intent_id": "intent:" + DIGEST[7:],
             "prompt_sha256": PROMPT, "turn_memory_status": "provisional",
             "turn_memory_registration_handoff": CONSENT, **(state_extra or {})}
    (tmp_path / (sha(THREAD) + ".json")).write_text(json.dumps(state), encoding="utf-8")
    return instance


def test_native_broker_hands_off_over_the_warm_stream(tmp_path, monkeypatch):
    broker = native_broker(tmp_path, monkeypatch, ok)
    broker._open_own_registration_after_admission()
    assert broker._post_admission_open_stage == "handed-off"
    [(method, params, timeout)] = broker.upstream.calls
    assert params == {"name": "integrity_turn_memory_open", "arguments": open_arguments()}
    assert timeout == broker.POST_ADMISSION_OPEN_TIMEOUT_SECONDS
    assert json.loads(handoff_path(tmp_path).read_text())["receipt"] == signed_receipt(open_arguments())


@pytest.mark.parametrize("sent", [False, True])
def test_native_broker_failure_writes_no_handoff_and_never_goes_cold(sent, tmp_path, monkeypatch):
    def broken(params):
        raise BrokerError("closed", layer="broker-upstream", request_sent=sent)

    broker = native_broker(tmp_path, monkeypatch, broken)
    broker._new_upstream = lambda *a: pytest.fail("post-admission open must not start a cold transport")
    broker._open_own_registration_after_admission()
    assert not handoff_path(tmp_path).exists() and len(broker.upstream.calls) == 1


@pytest.mark.parametrize("change", ["head", "state", "no-consent"])
def test_native_broker_skips_a_turn_that_is_not_its_current_one(change, tmp_path, monkeypatch):
    extra = {"state": {"model_mcp_context_admission_id": ADMISSION},
             "no-consent": {"turn_memory_registration_handoff": None}}.get(change)
    broker = native_broker(tmp_path, monkeypatch, ok, head_status="completed" if change == "head" else "inProgress",
                           state_extra=extra)
    broker._open_own_registration_after_admission()
    assert broker.upstream.calls == [] and not handoff_path(tmp_path).exists()


def native_hook(tmp_path, lifecycle):
    source = (RESOURCES / NATIVE_HOOK).read_text(encoding="utf-8")
    wanted = {"take_broker_registration_handoff", "open_admitted_turn_memory"}
    tree = ast.parse(source)
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    body += [n for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "TURN_REGISTRATION_HANDOFF_PROTOCOL" for t in n.targets)]
    socket = type("Socket", (), {"gethostname": staticmethod(lambda: "unit-host")})
    namespace = {"json": json, "re": re, "hashlib": hashlib, "time": __import__("time"), "socket": socket, "Any": object,
                 "HookError": HookError, "HookTransportError": HookTransportError, "state_root": lambda: tmp_path,
                 "sha256_text": sha, "save_state": lambda identity, state: None, "lifecycle_call": lifecycle,
                 "remaining_lifecycle_seconds": lambda seconds: None, "LIFECYCLE_BUDGET_SECONDS": 30,
                 "LIFECYCLE_DEADLINE": None,
                 "_is_digest": lambda v: isinstance(v, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", v) is not None}
    exec(compile(ast.Module(body=body, type_ignores=[]), NATIVE_HOOK, "exec"), namespace)
    return namespace["open_admitted_turn_memory"]


def test_native_hook_uses_the_handoff(tmp_path):
    calls = []
    open_turn = native_hook(tmp_path, lambda *a, **k: calls.append(a) or {})
    write_handoff(tmp_path)
    state = hook_state()
    assert open_turn(THREAD, state) == signed_receipt(open_arguments()) and calls == []
    assert not handoff_path(tmp_path).exists() and "turn_memory_unresolved_handle" not in state


def test_native_hook_without_handoff_opens_itself(tmp_path):
    calls = []
    open_turn = native_hook(tmp_path, lambda name, arguments, **o: calls.append(name)
                            or {"receipt": signed_receipt(arguments)})
    assert open_turn(THREAD, hook_state()) == signed_receipt(open_arguments())
    assert calls == ["integrity_turn_memory_open"]


@pytest.mark.parametrize("family", sorted(HOOKS))
def test_hook_rejects_a_handoff_whose_receipt_id_is_not_its_content_digest(family, tmp_path):
    calls = []

    def lifecycle(name, arguments, **owning):
        calls.append(name)
        return {"receipt": signed_receipt(arguments)}

    ns = hook_namespace(family, tmp_path, lifecycle)
    forged = {**signed_receipt(open_arguments()), "namespace_fingerprint": "sha256:" + "0" * 64}
    write_handoff(tmp_path, receipt=forged)
    state = hook_state()
    assert ns["open_admitted_turn_memory"](THREAD, state) == signed_receipt(open_arguments())
    assert calls == ["integrity_turn_memory_open"] and not handoff_path(tmp_path).exists()


@pytest.mark.parametrize("family", sorted(HOOKS))
def test_accepted_handoff_sets_no_unresolved_handle(family, tmp_path):
    ns = hook_namespace(family, tmp_path, lambda *a, **k: pytest.fail("no cold open"))
    write_handoff(tmp_path)
    state = hook_state()
    ns["open_admitted_turn_memory"](THREAD, state)
    assert "turn_memory_unresolved_handle" not in state


@pytest.mark.parametrize("path", [BROKERS["windows"], BROKERS["linux"], NATIVE_BROKER])
def test_failed_or_read_seal_admission_never_opens(path):
    """The open runs only inside the dispatch's ``if self.bound:`` branch.

    ``self.bound`` is false for an error result, which includes the read-seal
    retry denial, so neither an open nor a hand-off can follow it.
    """
    tree = ast.parse((RESOURCES / path).read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "_open_own_registration_after_admission"]
    assert len(calls) == 1
    guarded = [node for node in ast.walk(tree) if isinstance(node, ast.If)
               and ast.unparse(node.test) == "self.bound"
               and any(call in ast.walk(node) for call in calls)]
    assert guarded, "the post-admission open must sit under `if self.bound:`"
    inner = [node for node in ast.walk(guarded[-1]) if isinstance(node, ast.If)
             and ast.unparse(node.test) == "name == CURRENT_TURN_CONTEXT_TOOL"]
    assert any(call in ast.walk(node) for node in inner for call in calls)
