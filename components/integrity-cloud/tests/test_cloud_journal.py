"""integrity-cloud: journal, tamper detection, capsules, hooks and the CLI path."""
from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from integrity_cloud import capsule as capsule_mod
from integrity_cloud.cli import main
from integrity_cloud.hooks import hooks_config, install, run_hook
from integrity_cloud.journal import (Journal, JournalError, b64, record_hash, signing_bytes)
from integrity_cloud.scan import scan
from integrity_cloud.verify import import_plan, load_bundle, verify_bundle

NONCE = "a" * 32
# Secret-shaped probes are assembled at runtime so this file never carries one.
FAKE_GITHUB = "gh" + "p_" + "Z" * 36
FAKE_PRIVATE = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5
PRIVATE_V4 = ".".join(["10", "20", "30", "40"])


def sealed_bundle(tmp_path: Path, *, nonce: str = NONCE) -> dict:
    journal = Journal(tmp_path / "home")
    journal.open(nonce=nonce, label="unit", base_commit="f" * 40)
    journal.turn_open("fix the failing test")
    journal.event("thought", "root cause is a stale fixture", tags=["tests"])
    journal.event("action", "re-ran the suite", action={"target": "pytest", "result": "3 passed",
                                                        "exit_code": 0})
    journal.turn_close("events")
    journal.observation("hook:PostToolUse", tool_name="Bash", input_sha256="sha256:" + "0" * 64,
                        exit_code=0)
    journal.turn_open("explain the change")
    journal.turn_close("no-event", reason="read-only")
    out = journal.seal(tmp_path / "out" / "bundle.json")
    return load_bundle(Path(out["bundle"]))


def resign(bundle: dict, key_hex: str | None = None) -> None:
    """Re-chain after an edit with a different key: what a forger without the key can do."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    prev = "genesis"
    for record in bundle["records"]:
        record["prev"] = prev
        record["sig"] = b64(key.sign(signing_bytes(record)))
        prev = record_hash(record)


def test_sealed_journal_verifies_and_destroys_key(tmp_path):
    bundle = sealed_bundle(tmp_path)
    report = verify_bundle(bundle, expect_nonce=NONCE, expect_base_commit="f" * 40)
    assert report["verdict"] == "signed-chain-ok", report
    assert report["trust"] == "reported"
    assert (report["turns"], report["events"], report["observations"]) == (2, 2, 1)
    assert not (tmp_path / "home" / "signer.bin").exists()
    assert bundle["records"][-1]["type"] == "seal"


@pytest.mark.parametrize("mutate, reason", [
    (lambda b: b["records"][2]["body"].__setitem__("summary", "edited"), "bad_signature"),
    (lambda b: b["records"].pop(2), "sequence_gap"),
    (lambda b: b["records"].insert(2, b["records"].pop(3)), "sequence_gap"),
    (lambda b: b["records"].pop(), "unsealed"),
    (lambda b: b["records"][3]["body"].__setitem__("kind", "thought"), "bad_signature"),
])
def test_tampering_is_rejected(tmp_path, mutate, reason):
    bundle = sealed_bundle(tmp_path)
    mutate(bundle)
    report = verify_bundle(bundle)
    assert report["verdict"] == "rejected"
    assert any(reason in item for item in report["rejects"]), report["rejects"]


def test_resigning_with_another_key_is_rejected(tmp_path):
    bundle = sealed_bundle(tmp_path)
    bundle["records"][2]["body"]["summary"] = "forged"
    resign(bundle)
    report = verify_bundle(bundle)
    assert any("bad_signature" in r for r in report["rejects"])


def test_a_fully_rewritten_journal_still_needs_the_launch_nonce(tmp_path):
    forged = sealed_bundle(tmp_path / "forger", nonce="b" * 32)
    assert verify_bundle(forged)["verdict"] == "signed-chain-ok"
    assert "nonce_mismatch" in verify_bundle(forged, expect_nonce=NONCE)["rejects"]


def test_replayed_journal_is_rejected(tmp_path):
    bundle = sealed_bundle(tmp_path)
    report = verify_bundle(bundle, seen={bundle["journal_id"]})
    assert "journal_already_imported" in report["rejects"]


def test_turn_rules_are_enforced_at_write_time(tmp_path):
    journal = Journal(tmp_path / "home")
    with pytest.raises(JournalError):
        journal.turn_open("before open")
    journal.open(nonce=NONCE, base_commit="")
    journal.turn_open("one")
    with pytest.raises(JournalError):
        journal.turn_open("nested")
    with pytest.raises(JournalError):
        journal.turn_close("events")  # no events yet
    journal.event("task", "did a thing")
    with pytest.raises(JournalError):
        journal.turn_close("no-event", reason="read-only")
    with pytest.raises(JournalError):
        journal.seal(tmp_path / "b.json")  # open turn
    with pytest.raises(JournalError):
        journal.event("action", "no target")
    journal.turn_close("events")
    with pytest.raises(JournalError):
        journal.open(nonce=NONCE)  # still open


def test_event_outside_turn_opens_an_implicit_turn(tmp_path):
    journal = Journal(tmp_path / "home")
    journal.open(nonce=NONCE, base_commit="")
    journal.event("thought", "noted without turn-open")
    assert journal.state()["open_turn"] == 1
    journal.turn_close("events")
    bundle = load_bundle(Path(journal.seal(tmp_path / "o.json")["bundle"]))
    assert bundle["records"][1]["body"]["implicit"] is True
    assert verify_bundle(bundle)["verdict"] == "signed-chain-ok"


def test_receipt_must_list_exactly_its_turns_events(tmp_path):
    bundle = sealed_bundle(tmp_path)
    close = next(r for r in bundle["records"] if r["type"] == "turn_close")
    close["body"]["events"] = close["body"]["events"][:1]
    resign(bundle)
    bundle["public_key"] = bundle["records"][0]["body"]["public_key"]
    report = verify_bundle(bundle)
    assert any("receipt_events_mismatch" in r for r in report["rejects"])


def test_secrets_are_refused_not_masked(tmp_path):
    journal = Journal(tmp_path / "home")
    journal.open(nonce=NONCE, base_commit="")
    journal.turn_open("t")
    for text in (FAKE_GITHUB, FAKE_PRIVATE, "pass" + "word=hunter22"):
        with pytest.raises(JournalError) as caught:
            journal.event("thought", "found " + text)
        assert text not in str(caught.value)
    assert journal.state()["events"] == 0


def test_secret_injected_after_seal_is_rejected_by_verify(tmp_path):
    bundle = sealed_bundle(tmp_path)
    bundle["records"][2]["body"]["summary"] = FAKE_GITHUB
    report = verify_bundle(bundle)
    assert any(r.startswith("secret_like_content") for r in report["rejects"])
    assert FAKE_GITHUB not in json.dumps(report)


def test_import_plan_is_reported_and_idempotent(tmp_path):
    bundle = sealed_bundle(tmp_path)
    report = verify_bundle(bundle, expect_nonce=NONCE)
    plan = import_plan(bundle, report, verified_utc="2026-11-04T00:00:00Z")
    uids = [e["event_uid"] for e in plan["events"]]
    assert uids[0] == f"client:cloud-{bundle['journal_id']}-journal"
    assert len(uids) == 3 and len(set(uids)) == 3
    action = plan["events"][2]
    assert action["kind"] == "task" and "cloud-action" in action["tags"]
    assert action["details"]["provenance"]["trust"] == "reported"
    assert action["details"]["reported_action"]["target"] == "pytest"
    assert all(e["summary"].startswith("[cloud-agent, reported]") for e in plan["events"])
    assert plan == import_plan(bundle, report, verified_utc="2026-11-04T00:00:00Z")
    rejected = verify_bundle(copy.deepcopy(bundle), expect_nonce="c" * 32)
    with pytest.raises(ValueError):
        import_plan(bundle, rejected)


def test_capsule_build_load_and_privacy_refusals(tmp_path):
    items = [{"event_uid": "client:x-00000001", "kind": "thought", "summary": "use pytest -q",
              "tags": ["tests"], "details": {"host": PRIVATE_V4}}]
    built = capsule_mod.build(items, purpose="unit")
    assert built["items"][0] == {"uid": "client:x-00000001", "kind": "thought",
                                 "summary": "use pytest -q", "tags": ["tests"]}
    path = tmp_path / "capsule.json"
    path.write_text(json.dumps(built), encoding="utf-8")
    assert capsule_mod.load(path)["nonce"] == built["nonce"]
    edited = dict(built, purpose="changed")
    path.write_text(json.dumps(edited), encoding="utf-8")
    with pytest.raises(capsule_mod.CapsuleError):
        capsule_mod.load(path)
    for summary in (f"router at {PRIVATE_V4}", FAKE_GITHUB):
        with pytest.raises(capsule_mod.CapsuleError) as caught:
            capsule_mod.build([{"summary": summary}], purpose="unit")
        assert summary not in str(caught.value)
    with pytest.raises(capsule_mod.CapsuleError):
        capsule_mod.build([{"summary": "core-sw.internal is the spine"}], purpose="unit",
                          deny_literals=("core-sw.internal",))
    assert capsule_mod.build([{"summary": "docs use 192.0.2.1"}], purpose="u")


def test_journal_binds_the_capsule(tmp_path):
    built = capsule_mod.build([{"summary": "context"}], purpose="unit")
    journal = Journal(tmp_path / "home")
    journal.open(capsule=built, base_commit="")
    journal.turn_open("t")
    journal.turn_close("no-event", reason="read-only")
    bundle = load_bundle(Path(journal.seal(tmp_path / "b.json")["bundle"]))
    ok = verify_bundle(bundle, expect_nonce=built["nonce"], expect_capsule=built["sha256"])
    assert ok["verdict"] == "signed-chain-ok"
    bad = verify_bundle(bundle, expect_capsule="sha256:" + "1" * 64)
    assert "capsule_mismatch" in bad["rejects"]


def test_scan_ignores_times_versions_and_documentation_addresses():
    version = ".".join(["1", "2", "3", "400"])  # four dotted parts, not an address
    assert scan({"a": f"built {version} at 2026-11-04T16:27:37Z"}) == []
    assert scan({"a": f"built {version}"}, network=True) == []
    assert scan({"a": "203.0.113.7 and 2001:db8::1"}, network=True) == []
    assert scan({"a": PRIVATE_V4}, network=True)


def test_hooks_observe_remind_and_block_stop_once(tmp_path):
    journal = Journal(tmp_path / "home")
    out, status = run_hook("SessionStart", json.dumps({"source": "startup"}), journal)
    assert status == 0 and "integrity-cloud open" in out
    journal.open(nonce=NONCE, base_commit="")
    run_hook("UserPromptSubmit", json.dumps({"prompt": "do x", "turn_id": "t1"}), journal)
    assert journal.state()["open_turn"] == 1
    run_hook("PostToolUse", json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"},
                                        "tool_response": {"exit_code": 0}}), journal)
    out, status = run_hook("Stop", json.dumps({"stop_hook_active": False}), journal)
    assert status == 0 and json.loads(out)["decision"] == "block"
    out, _ = run_hook("Stop", json.dumps({"stop_hook_active": True}), journal)
    assert out == ""
    records = journal.records()
    assert "do x" not in json.dumps(records) and '"ls"' not in json.dumps(records)
    assert run_hook("PostToolUse", "not json", journal) == ("", 0)


def test_hooks_install_merges_and_is_idempotent(tmp_path):
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [
        {"hooks": [{"type": "command", "command": "true"}]}]}}), encoding="utf-8")
    first = install(codex, python="/usr/bin/python3")
    second = install(codex, python="/usr/bin/python3")
    data = json.loads((codex / "hooks.json").read_text(encoding="utf-8"))
    assert set(first["added"]) == set(hooks_config()["hooks"]) and second["added"] == []
    assert len(data["hooks"]["Stop"]) == 2


def run_cli(*argv: str) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(list(argv))
    return code, buffer.getvalue()


def test_cli_end_to_end_with_capsule(tmp_path, monkeypatch):
    home = str(tmp_path / "home")
    source = tmp_path / "events.json"
    source.write_text(json.dumps({"events": [{"event_uid": "client:a-00000001",
                                              "kind": "concept", "summary": "be brief"}]}),
                      encoding="utf-8")
    cap = tmp_path / "capsule.json"
    assert run_cli("capsule", "build", "--input", str(source), "--purpose", "e2e",
                   "--out", str(cap))[0] == 0
    built = json.loads(cap.read_text(encoding="utf-8"))
    monkeypatch.chdir(tmp_path)
    assert run_cli("--home", home, "open", "--capsule", str(cap), "--label", "e2e")[0] == 0
    code, out = run_cli("--home", home, "context")
    assert code == 0 and json.loads(out)["items"][0]["summary"] == "be brief"
    assert run_cli("--home", home, "turn-open", "--intent", "update docs")[0] == 0
    assert run_cli("--home", home, "event", "--kind", "action", "--summary", "edited README",
                   "--target", "README.md", "--result", "1 section added")[0] == 0
    assert run_cli("--home", home, "turn-close", "--outcome", "events")[0] == 0
    code, out = run_cli("--home", home, "seal", "--out", "integrity-journal/")
    bundle_path = Path(json.loads(out)["bundle"])
    assert code == 0 and bundle_path.parent.name == "integrity-journal"
    seen = tmp_path / "seen.txt"
    code, out = run_cli("import-plan", str(bundle_path), "--expect-nonce", built["nonce"],
                        "--expect-capsule", built["sha256"], "--seen", str(seen),
                        "--record-seen", "--out", str(tmp_path / "plan.json"))
    assert code == 0 and json.loads(out)["events"] == 2
    code, out = run_cli("verify", str(bundle_path), "--seen", str(seen))
    assert code == 1 and "journal_already_imported" in json.loads(out)["rejects"]
    assert run_cli("--home", home, "turn-open", "--intent", "after seal")[0] == 2


def test_bootstrap_creates_no_key_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEGRITY_CLOUD_HOME", str(tmp_path / "journal-home"))
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("alias ll='ls -l'\n", encoding="utf-8")
    for _ in range(2):
        code, out = run_cli("bootstrap", "--bashrc", str(bashrc),
                            "--codex-home", str(tmp_path / ".codex"))
        assert code == 0 and json.loads(out)["self_test"] == "signed-chain-ok"
    text = bashrc.read_text(encoding="utf-8")
    assert text.count("# >>> integrity-cloud >>>") == 1 and "export INTEGRITY_CLOUD=1" in text
    assert text.startswith("alias ll=")
    assert not (tmp_path / "journal-home").exists()


def test_module_entrypoint_runs_as_hook(tmp_path):
    env = dict(os.environ, INTEGRITY_CLOUD_HOME=str(tmp_path / "h"), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-B", "-m", "integrity_cloud", "hook", "SessionStart"],
                            input="{}", capture_output=True, text=True, env=env, timeout=60,
                            check=False)
    assert result.returncode == 0 and "integrity-cloud open" in result.stdout
