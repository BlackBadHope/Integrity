"""Two client machines claim work at one core through an OpenSSH forced command.

Machine A runs one claims core in strict mode behind an ``integrity-remote``
release. Machine B holds two device keys (``laptop-a`` and ``laptop-b``) and
the agent keys; each agent key is enrolled at the core for one device. A
non-root ``sshd`` on loopback stands in for the network, as in
``tests/test_two_machine_ssh.py``. Every session below is a real ``ssh``
connection whose command is fixed by ``authorized_keys``.

Set INTEGRITY_REMOTE_E2E_REQUIRED=1 to turn a missing OpenSSH into a failure.
"""
from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from integrity_guardian.claims_client import ClaimsClient, ClaimsClientError
from integrity_guardian.claims_core import init, open_core, server_spec
from integrity_guardian.work_claim_identity import AgentKey, sign_request

REQUIRED = os.environ.get("INTEGRITY_REMOTE_E2E_REQUIRED") == "1"


def _tool(name: str, *extra: str) -> str:
    found = shutil.which(name) or next((p for p in extra if os.access(p, os.X_OK)), None)
    if not found:
        message = f"OpenSSH {name} is not installed"
        if REQUIRED:
            pytest.fail(message)
        pytest.skip(message)
    return found


def _cli(*args: str) -> str:
    done = subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True,
                          timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout


def _keygen(keygen: str, path: Path, comment: str) -> list[str]:
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                   check=True, stdin=subprocess.DEVNULL)
    return path.with_suffix(".pub").read_text().split()[:2]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def machines(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        if REQUIRED:
            pytest.fail("the forced-command core side is Linux-only")
        pytest.skip("the forced-command core side is Linux-only")
    try:
        import integrity_remote  # noqa: F401
    except ImportError:
        if REQUIRED:
            pytest.fail("integrity_remote is not installed")
        pytest.skip("integrity_remote is not installed")
    ssh, keygen = _tool("ssh"), _tool("ssh-keygen")
    sshd = _tool("sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd")
    base = tmp_path_factory.mktemp("networked-claims")
    a, b = base / "machine-a", base / "machine-b"
    for folder in (a, b):
        folder.mkdir(mode=0o700)
    host_key = _keygen(keygen, a / "host_ed25519", "claims-core-host")
    for device in ("laptop-a", "laptop-b"):
        _keygen(keygen, b / f"{device}_ed25519", device)

    home = a / "claims-core"
    init(home, identity_mode="strict")
    spec = a / "claims-server.json"
    spec.write_text(json.dumps(server_spec(home)))
    release = json.loads(_cli("integrity_remote", "core", "init", "--root", str(a / "release"),
                              "--server-json", str(spec), "--max-sessions", "8"))["release"]
    lines = "".join(
        _cli("integrity_remote", "authorize", "--release", release, "--device-id", device,
             "--public-key", str(b / f"{device}_ed25519.pub"))
        for device in ("laptop-a", "laptop-b")
    )
    authorized = a / "authorized_keys"
    authorized.write_text(lines)
    authorized.chmod(0o600)

    agents = {"agent-a": "laptop-a", "agent-b": "laptop-b", "agent-c": "laptop-a"}
    keys = {name: AgentKey.generate() for name in [*agents, "stranger"]}
    with open_core(home) as gate:
        for name, device in agents.items():
            gate.enroll(agent_id=name, public_key=keys[name].public_value, devices=[device])

    port = _free_port()
    config = a / "sshd_config"
    config.write_text("\n".join([
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {a / 'host_ed25519'}",
        f"PidFile {a / 'sshd.pid'}", f"AuthorizedKeysFile {authorized}",
        f"AllowUsers {getpass.getuser()}", "AuthenticationMethods publickey",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "PermitRootLogin no", "PermitUserEnvironment no", "StrictModes no", "LogLevel VERBOSE",
        "MaxStartups 32", "MaxSessions 32", ""]))
    log = open(a / "sshd.log", "wb")
    daemon = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdin=subprocess.DEVNULL,
                              stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if daemon.poll() is not None or time.monotonic() > deadline:
                log.close()
                pytest.fail("sshd did not start: " + (a / "sshd.log").read_text()[-2000:])
            time.sleep(0.1)
    known = b / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {' '.join(host_key)}\n")

    def upstream(device: str) -> list[str]:
        out = b / f"upstream-{device}-{uuid.uuid4().hex[:6]}.json"
        _cli("integrity_remote", "client-upstream", "--host", "127.0.0.1", "--port", str(port),
             "--user", getpass.getuser(), "--identity", str(b / f"{device}_ed25519"),
             "--known-hosts", str(known), "--ssh", ssh, "--output", str(out))
        spec = json.loads(out.read_text())
        return [spec["command"], *spec["args"]]

    def connect(agent: str, device: str | None = None, key: str | None = None) -> ClaimsClient:
        return ClaimsClient(upstream(device or agents[agent]), agent_id=agent,
                            key=keys[key or agent], timeout=60)

    try:
        yield {"home": home, "keys": keys, "connect": connect, "sshd_log": a / "sshd.log"}
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
        log.close()


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


def refused(code: str, call, *args) -> None:
    with pytest.raises(ClaimsClientError) as caught:
        call(*args)
    assert caught.value.code == code, caught.value


def test_each_session_carries_the_device_fixed_by_authorized_keys(machines) -> None:
    with machines["connect"]("agent-a") as a, machines["connect"]("agent-b") as b:
        assert (a.device_id, b.device_id) == ("laptop-a", "laptop-b")
        assert a.core_id == b.core_id and a.identity_mode == "strict"


def test_two_machines_race_for_one_task_and_one_wins(machines) -> None:
    with machines["connect"]("agent-a") as a, machines["connect"]("agent-b") as b:
        fences = []
        for number in range(3):
            results = race([a, b], f"task:ssh-race-{number}")
            assert sorted(item["status"] for item in results) == ["acquired", "waiting"]
            fences.append(next(item["fence_token"] for item in results
                               if item["status"] == "acquired"))
        assert fences == sorted(fences) and len(set(fences)) == 3


def test_lease_expiry_over_ssh_fences_out_the_stale_holder(machines) -> None:
    with machines["connect"]("agent-a") as a, machines["connect"]("agent-b") as b:
        held = a.claim(["task:ssh-lease"], ttl_seconds=1)
        time.sleep(1.6)
        taken = b.claim(["task:ssh-lease"], ttl_seconds=60)
        assert taken["status"] == "acquired" and taken["fence_token"] > held["fence_token"]
        refused("stale-fence", a.record, held["claim_id"], held["fence_token"], "late result")
        b.record(taken["claim_id"], taken["fence_token"], "result from the new holder")
        b.release(taken["claim_id"], taken["fence_token"], "done")


def test_forged_signature_over_ssh_is_rejected(machines) -> None:
    with machines["connect"]("agent-a") as a:
        request = a.sign("claim", {"resources": ["task:ssh-forged"]})
        request["arguments"]["resources"] = ["task:ssh-other"]
        refused("bad-signature", a.send, request)
        stranger = sign_request(machines["keys"]["stranger"], core_id=a.core_id,
                                agent_id="agent-a", operation="claim",
                                arguments={"resources": ["task:ssh-forged"]})
        stranger["key_id"] = stranger["signature"]["key_id"] = machines["keys"]["agent-a"].key_id
        refused("bad-signature", a.send, stranger)


def test_replay_in_a_new_ssh_session_is_rejected(machines) -> None:
    with machines["connect"]("agent-a") as a:
        request = a.sign("claim", {"resources": ["task:ssh-replay"], "ttl_seconds": 60})
        assert a.send(request)["status"] == "acquired"
    with machines["connect"]("agent-a") as again:
        refused("replay", again.send, request)


def test_agent_key_from_another_device_is_rejected(machines) -> None:
    with machines["connect"]("agent-a", device="laptop-b") as wrong:
        assert wrong.device_id == "laptop-b"
        refused("device-mismatch", wrong.claim, ["task:ssh-device"])


def test_revoked_agent_key_is_rejected_over_ssh(machines) -> None:
    with machines["connect"]("agent-c") as c:
        held = c.claim(["task:ssh-revoke"], ttl_seconds=60)
        _cli("integrity_guardian.claims_core", "revoke", "--home", str(machines["home"]),
             "--key-id", machines["keys"]["agent-c"].key_id)
        refused("key-revoked", c.record, held["claim_id"], held["fence_token"], "after revoke")
    with machines["connect"]("agent-c") as again:
        refused("key-revoked", again.claim, ["task:ssh-revoke-2"])


def test_core_log_names_the_device_of_every_signed_request(machines) -> None:
    with machines["connect"]("agent-b") as b:
        b.claim(["task:ssh-audit"], ttl_seconds=60)
    report = json.loads(_cli("integrity_guardian.claims_core", "verify", "--home",
                             str(machines["home"])))
    assert report["ok"] is True and report["signed_requests"] >= 1
    with open_core(machines["home"]) as gate:
        devices = {event["requested_by"].get("device_id") for event in gate.registry.events()
                   if event.get("requested_by", {}).get("mode") == "verified"}
    assert devices <= {"laptop-a", "laptop-b"} and "laptop-b" in devices
