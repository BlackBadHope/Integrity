"""Signed agent identity for work claims, against one real claims core process.

Every client here is its own ``guardian-claims-core serve`` process on stdio,
so two clients are two sessions writing one claim database, as two machines
would through a forced command (``tests/test_networked_claims_ssh.py`` runs
the same checks through ``sshd``). Runs on Linux and Windows.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from integrity_guardian.claims_client import ClaimsClient, ClaimsClientError, local_core_argv
from integrity_guardian.claims_core import init, open_core
from integrity_guardian.work_claim_identity import (
    AgentKey,
    ClaimRequestRejected,
    SignedClaimGate,
    sign_request,
)
from integrity_guardian.work_claims import (
    StaleFenceError,
    UnsignedClaimError,
    WorkClaimError,
    WorkClaimRegistry,
)

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _cli(module: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", module, *args], capture_output=True,
                          text=True, timeout=60)


@pytest.fixture
def core(tmp_path: Path) -> dict:
    home = tmp_path / "core"
    init(home, identity_mode="strict")
    keys = {name: AgentKey.generate() for name in ("agent-a", "agent-b", "stranger")}
    with open_core(home) as gate:
        for name in ("agent-a", "agent-b"):
            gate.enroll(agent_id=name, public_key=keys[name].public_value)
    return {"home": home, "keys": keys}


def client(core: dict, agent: str, key: str | None = None) -> ClaimsClient:
    chosen = core["keys"][key or agent] if (key or agent) in core["keys"] else None
    return ClaimsClient(local_core_argv(core["home"]), agent_id=agent, key=chosen)


def refused(code: str, call, *args, **kwargs) -> ClaimsClientError:
    with pytest.raises(ClaimsClientError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == code, caught.value
    return caught.value


def race(sessions: list[ClaimsClient], resource: str) -> list[dict]:
    """Send one claim from every session at the same moment."""

    barrier = threading.Barrier(len(sessions))
    results: list[dict] = []

    def contend(session: ClaimsClient) -> None:
        barrier.wait()
        results.append(session.claim([resource], ttl_seconds=60))

    threads = [threading.Thread(target=contend, args=(session,)) for session in sessions]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(90)
    assert len(results) == len(sessions), "a racing session did not answer"
    return results


def test_two_clients_race_for_one_task_one_wins(core) -> None:
    a, b = client(core, "agent-a"), client(core, "agent-b")
    try:
        fences = []
        for round_number in range(5):
            results = {str(i): item for i, item in
                       enumerate(race([a, b], f"task:race-{round_number}"))}
            statuses = sorted(item["status"] for item in results.values())
            assert statuses == ["acquired", "waiting"], results
            winner = next(item for item in results.values() if item["status"] == "acquired")
            loser = next(item for item in results.values() if item["status"] == "waiting")
            assert loser["blocked_by"] == [winner["claim_id"]]
            assert winner["identity"] == loser["identity"] == "verified"
            fences.append(winner["fence_token"])
        assert fences == sorted(fences) and len(set(fences)) == len(fences)
    finally:
        a.close()
        b.close()
    with open_core(core["home"]) as gate:
        audit = gate.verify_log()
    assert audit["signed_requests"] == 10 and audit["verified_events"] >= 10


def test_lease_expiry_hands_the_task_over_and_fences_out_the_old_holder(core) -> None:
    with client(core, "agent-a") as a, client(core, "agent-b") as b:
        held = a.claim(["task:lease"], ttl_seconds=1)
        assert held["status"] == "acquired"
        waiting = b.claim(["task:lease"], ttl_seconds=30)
        assert waiting["status"] == "waiting"
        time.sleep(1.6)
        taken = b.poll(waiting["claim_id"])
        assert taken["status"] == "acquired" and taken["fence_token"] > held["fence_token"]
        refused("stale-fence", a.record, held["claim_id"], held["fence_token"], "late result")
        refused("stale-fence", a.release, held["claim_id"], held["fence_token"], "late")
        refused("stale-fence", a.renew, held["claim_id"], held["fence_token"])
        written = b.record(taken["claim_id"], taken["fence_token"], "result from b")
        assert written["receipt"]["kind"] == "claim-result-recorded"
        kinds = [event["kind"] for event in b.events()]
        assert "claim-expired" in kinds and kinds.count("claim-result-recorded") == 1
        assert a.status(held["claim_id"])["status"] == "expired"


def test_handoff_moves_the_task_and_the_predecessor_cannot_write(core) -> None:
    with client(core, "agent-a") as a, client(core, "agent-b") as b:
        held = a.claim(["task:handoff"], ttl_seconds=60)
        refused("unknown-successor", a.handoff, held["claim_id"], held["fence_token"], "nobody")
        moved = a.handoff(held["claim_id"], held["fence_token"], "agent-b", "shift change")
        assert moved["agent_id"] == "agent-b" and moved["fence_token"] > held["fence_token"]
        refused("stale-fence", a.record, held["claim_id"], held["fence_token"], "too late")
        refused("stale-fence", a.record, moved["claim_id"], moved["fence_token"], "not mine")
        b.assert_fence(moved["claim_id"], moved["fence_token"])
        b.release(moved["claim_id"], moved["fence_token"], "done")


def test_forged_signature_is_rejected(core) -> None:
    with client(core, "agent-a") as a:
        signed = a.sign("claim", {"resources": ["task:forged"], "ttl_seconds": 60})
        tampered = json.loads(json.dumps(signed))
        tampered["arguments"]["resources"] = ["task:other"]
        refused("bad-signature", a.send, tampered)
        stranger = core["keys"]["stranger"]
        impostor = sign_request(stranger, core_id=a.core_id, agent_id="agent-a",
                                operation="claim", arguments={"resources": ["task:forged"]})
        impostor["key_id"] = core["keys"]["agent-a"].key_id
        impostor["signature"]["key_id"] = core["keys"]["agent-a"].key_id
        refused("bad-signature", a.send, impostor)
        own = sign_request(stranger, core_id=a.core_id, agent_id="stranger",
                           operation="claim", arguments={"resources": ["task:forged"]})
        refused("unknown-key", a.send, own)
        as_b = sign_request(core["keys"]["agent-a"], core_id=a.core_id, agent_id="agent-b",
                            operation="claim", arguments={"resources": ["task:forged"]})
        refused("agent-mismatch", a.send, as_b)
        assert a.send(signed)["status"] == "acquired"  # the untouched original still works


def test_replay_is_rejected_in_the_same_and_in_another_session(core) -> None:
    with client(core, "agent-a") as a:
        request = a.sign("claim", {"resources": ["task:replay"], "ttl_seconds": 60})
        first = a.send(request)
        assert first["status"] == "acquired"
        refused("replay", a.send, request)
        stale = a.sign("record", {"claim_id": first["claim_id"], "fence_token": 999,
                                  "result": "x"})
        refused("stale-fence", a.send, stale)
        refused("replay", a.send, stale)  # a refused request is consumed too
    with client(core, "agent-a") as again:
        refused("replay", again.send, request)
    with open_core(core["home"]) as gate:
        kinds = [event["kind"] for event in gate.registry.events()]
    assert kinds.count("claim-acquired") == 1 and "claim-request-failed" in kinds


def test_revoked_key_is_rejected_while_its_session_is_open(core) -> None:
    with client(core, "agent-a") as a:
        held = a.claim(["task:revoke"], ttl_seconds=60)
        key_id = core["keys"]["agent-a"].key_id
        done = _cli("integrity_guardian.claims_core", "revoke", "--home", str(core["home"]),
                    "--key-id", key_id)
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout)["status"] == "revoked"
        refused("key-revoked", a.record, held["claim_id"], held["fence_token"], "after revoke")
        refused("key-revoked", a.claim, ["task:other"])
    with open_core(core["home"]) as gate:
        with pytest.raises(WorkClaimError):
            gate.enroll(agent_id="agent-a", public_key=core["keys"]["agent-a"].public_value)


def test_strict_core_refuses_unsigned_and_declared_core_marks_it(core, tmp_path) -> None:
    with ClaimsClient(local_core_argv(core["home"]), agent_id="agent-a") as unsigned:
        assert unsigned.identity_mode == "strict"
        refused("unsigned-refused", unsigned.claim, ["task:x"])
    declared = tmp_path / "declared"
    init(declared, identity_mode="declared")
    with ClaimsClient(local_core_argv(declared), agent_id="anyone") as named:
        result = named.claim(["task:x"])
        assert result["identity"] == "declared" and result["agent_id"] == "anyone"
        assert named.events()[0]["requested_by"] == {"mode": "declared"}


def test_declared_core_refuses_unsigned_requests_for_an_enrolled_agent(tmp_path) -> None:
    home = tmp_path / "declared"
    init(home, identity_mode="declared")
    keys = {name: AgentKey.generate() for name in ("agent-a", "agent-r")}
    with open_core(home) as gate:
        gate.enroll(agent_id="agent-a", public_key=keys["agent-a"].public_value)
        revoked = gate.enroll(agent_id="agent-r", public_key=keys["agent-r"].public_value)
        gate.revoke(revoked.key_id)
    argv = local_core_argv(home)
    with ClaimsClient(argv, agent_id="agent-a", key=keys["agent-a"]) as signed, \
            ClaimsClient(argv, agent_id="agent-a") as impostor, \
            ClaimsClient(argv, agent_id="agent-r") as after_revoke, \
            ClaimsClient(argv, agent_id="someone") as named:
        held = signed.claim(["task:enrolled"], ttl_seconds=60)
        assert held["identity"] == "verified"
        refused("enrolled-agent-must-sign", impostor.cancel, held["claim_id"])
        refused("enrolled-agent-must-sign", impostor.poll, held["claim_id"])
        refused("enrolled-agent-must-sign", impostor.release, held["claim_id"],
                held["fence_token"], "taken over")
        refused("enrolled-agent-must-sign", impostor.claim, ["task:other"])
        refused("enrolled-agent-must-sign", after_revoke.claim, ["task:other"])
        assert named.claim(["task:other"])["identity"] == "declared"
        assert signed.status(held["claim_id"])["status"] == "acquired"


def test_refused_request_is_consumed_in_the_same_transaction(tmp_path) -> None:
    path = tmp_path / "claims.sqlite"
    key = AgentKey.generate()
    with WorkClaimRegistry(path, identity_mode="strict") as registry:
        gate = SignedClaimGate(registry, core_id="claims-core:test")
        gate.enroll(agent_id="agent-a", public_key=key.public_value, now=T0)
        held = gate.execute(
            sign_request(key, core_id="claims-core:test", agent_id="agent-a",
                         operation="claim", arguments={"resources": ["task:sp"]}, now=T0),
            now=T0,
        )
        stale = sign_request(key, core_id="claims-core:test", agent_id="agent-a",
                             operation="record", now=T0,
                             arguments={"claim_id": held["claim_id"], "fence_token": 999,
                                        "result": "late"})
        with pytest.raises(StaleFenceError):
            gate.execute(stale, now=T0)
        assert not registry._connection.in_transaction
        with pytest.raises(ClaimRequestRejected) as caught:
            gate.execute(stale, now=T0)
        assert caught.value.code == "replay"
        outcomes = registry._connection.execute(
            "SELECT outcome FROM work_claim_requests ORDER BY received_at, outcome"
        ).fetchall()
        assert sorted(row["outcome"] for row in outcomes) == ["accepted", "refused"]
        kinds = [event["kind"] for event in registry.events()]
        assert kinds.count("claim-request-failed") == 1
        assert "claim-result-recorded" not in kinds
        assert gate.verify_log()["signed_requests"] == 2


def test_strict_mode_is_sticky_and_guards_direct_use(tmp_path) -> None:
    path = tmp_path / "claims.sqlite"
    with WorkClaimRegistry(path) as registry:
        assert registry.identity_mode == "declared"
    with WorkClaimRegistry(path, identity_mode="strict") as registry:
        with pytest.raises(UnsignedClaimError):
            registry.claim(agent_id="agent-a", resources=["task:x"])
    with WorkClaimRegistry(path) as registry:
        assert registry.identity_mode == "strict"
    with pytest.raises(WorkClaimError):
        WorkClaimRegistry(path, identity_mode="declared")


def test_validity_window_audience_and_device_binding(tmp_path) -> None:
    key, other = AgentKey.generate(), AgentKey.generate()
    with WorkClaimRegistry(tmp_path / "c.sqlite", identity_mode="strict") as registry:
        gate = SignedClaimGate(registry, core_id="claims-core:test")
        gate.enroll(agent_id="agent-a", public_key=key.public_value, devices=["laptop-a"])
        gate.enroll(agent_id="agent-b", public_key=other.public_value)

        def request(**options):
            return sign_request(key, core_id=options.pop("core_id", "claims-core:test"),
                                agent_id="agent-a", operation="claim",
                                arguments={"resources": ["task:w"]}, **options)

        def code(req, *, device="laptop-a", now=T0):
            with pytest.raises(ClaimRequestRejected) as caught:
                gate.execute(req, device_id=device, now=now)
            return caught.value.code

        assert code(request(now=T0 - timedelta(seconds=120), lifetime_seconds=60)) == "expired"
        assert code(request(now=T0 + timedelta(seconds=120))) == "not-yet-valid"
        assert code(request(now=T0, core_id="claims-core:elsewhere")) == "wrong-core"
        long = request(now=T0)
        long["expires_at"] = "2026-11-01T13:00:00.000000Z"
        assert code(long) == "bad-signature"  # the window is signed
        assert code(request(now=T0), device="laptop-b") == "device-mismatch"
        assert code(request(now=T0), device="") == "device-mismatch"
        accepted = gate.execute(request(now=T0), device_id="laptop-a", now=T0)
        assert accepted["status"] == "acquired"
        free = sign_request(other, core_id="claims-core:test", agent_id="agent-b",
                            operation="claim", arguments={"resources": ["task:v"]}, now=T0)
        assert gate.execute(free, device_id="any-device", now=T0)["status"] == "acquired"
        event = registry.events()[-1]
        assert event["requested_by"]["device_id"] == "any-device"
        assert gate.verify_log()["signed_requests"] == 2


def test_device_comes_from_the_forced_command_environment(tmp_path) -> None:
    home, key = tmp_path / "core", AgentKey.generate()
    init(home, identity_mode="strict")
    with open_core(home) as gate:
        gate.enroll(agent_id="agent-a", public_key=key.public_value, devices=["laptop-a"])

    def session(device: str) -> ClaimsClient:
        env = {**os.environ, "INTEGRITY_REMOTE_DEVICE_ID": device}
        return ClaimsClient(local_core_argv(home), agent_id="agent-a", key=key, env=env)

    with session("laptop-b") as wrong:
        assert wrong.device_id == "laptop-b"
        refused("device-mismatch", wrong.claim, ["task:device"])
    with session("laptop-a") as right:
        assert right.claim(["task:device"])["status"] == "acquired"
        assert right.events()[-1]["requested_by"]["device_id"] == "laptop-a"


def test_tampered_stored_request_fails_the_audit(core) -> None:
    with client(core, "agent-a") as a:
        a.claim(["task:audit"])
    with open_core(core["home"]) as gate:
        gate._db.execute("UPDATE work_claim_requests SET request_json = "
                         "replace(request_json, 'task:audit', 'task:other')")
        with pytest.raises(WorkClaimError):
            gate.verify_log()


def test_command_line_keygen_enroll_claim(tmp_path) -> None:
    home, key = tmp_path / "core", tmp_path / "agent.key"
    assert _cli("integrity_guardian.claims_core", "init", "--home", str(home),
                "--identity", "strict").returncode == 0
    made = _cli("integrity_guardian.claims_client", "keygen", "--out", str(key))
    assert made.returncode == 0, made.stderr
    enrolled = _cli("integrity_guardian.claims_core", "enroll", "--home", str(home),
                    "--agent-id", "agent-cli", "--public-key", str(key) + ".pub")
    assert enrolled.returncode == 0, enrolled.stderr
    assert json.loads(enrolled.stdout)["key_id"] == json.loads(made.stdout)["key_id"]
    claimed = _cli("integrity_guardian.claims_client", "claim", "--core-home", str(home),
                   "--agent-id", "agent-cli", "--key", str(key), "--resource", "task:cli")
    assert claimed.returncode == 0, claimed.stderr
    assert json.loads(claimed.stdout)["identity"] == "verified"
    unsigned = _cli("integrity_guardian.claims_client", "claim", "--core-home", str(home),
                    "--agent-id", "agent-cli", "--resource", "task:cli2")
    assert unsigned.returncode == 1
    assert json.loads(unsigned.stdout)["code"] == "unsigned-refused"
    verified = _cli("integrity_guardian.claims_core", "verify", "--home", str(home))
    assert verified.returncode == 0 and json.loads(verified.stdout)["signed_requests"] == 1


def test_gate_rejects_stale_fence_without_a_session(tmp_path) -> None:
    key = AgentKey.generate()
    with WorkClaimRegistry(tmp_path / "c.sqlite", identity_mode="strict") as registry:
        gate = SignedClaimGate(registry, core_id="claims-core:test")
        gate.enroll(agent_id="agent-a", public_key=key.public_value)
        held = gate.execute(sign_request(key, core_id="claims-core:test", agent_id="agent-a",
                                         operation="claim",
                                         arguments={"resources": ["task:f"], "ttl_seconds": 5},
                                         now=T0), now=T0)
        late = sign_request(key, core_id="claims-core:test", agent_id="agent-a",
                            operation="record", now=T0 + timedelta(seconds=6),
                            arguments={"claim_id": held["claim_id"],
                                       "fence_token": held["fence_token"], "result": "late"})
        with pytest.raises(StaleFenceError):
            gate.execute(late, now=T0 + timedelta(seconds=6))
