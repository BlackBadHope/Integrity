"""humanx_delivery and humanx_topics: adapted from the pilot unit suite (U group) to a synthetic room."""
import json
import os
import sys
import time

import pytest

import humanx_delivery as DL

# A tiny room_tool stand-in written here (the pilot stub is not shipped): it records each call in
# journal/stub-calls.jsonl, can fail an op N times and can answer in cp866 (Russian console output).
STUB = r'''
import json, os, sys
room = os.getcwd()
op, rel = sys.argv[1], sys.argv[2]
args = json.load(open(os.path.join(room, rel), encoding="utf-8"))
ctl = {}
if os.path.exists(os.path.join(room, "stub-ctl.json")):
    ctl = json.load(open(os.path.join(room, "stub-ctl.json"), encoding="utf-8"))
with open(os.path.join(room, "journal", "stub-calls.jsonl"), "a", encoding="utf-8") as f:
    f.write(json.dumps({"op": op, "args": args}, ensure_ascii=False) + "\n")
left = ctl.get("fail_ops", {}).get(op, 0)
if left:
    ctl["fail_ops"][op] = left - 1
    json.dump(ctl, open(os.path.join(room, "stub-ctl.json"), "w", encoding="utf-8"))
    sys.stdout.write(json.dumps({"ok": False, "error": "stub-fail"}) + "\n")
    sys.exit(1)
text = json.dumps({"ok": True, "note": "готово"}, ensure_ascii=False) + "\n"
sys.stdout.buffer.write(text.encode("cp866" if ctl.get("cp866") else "utf-8"))
'''


def stub_room(tmp_path, ctl=None):
    d = tmp_path / "room"
    (d / "journal").mkdir(parents=True)
    (d / "work").mkdir()
    (d / "room_tool.py").write_text(STUB, encoding="utf-8")
    if ctl:
        (d / "stub-ctl.json").write_text(json.dumps(ctl), encoding="utf-8")
    return d


def calls(room):
    p = room / "journal" / "stub-calls.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def _ev(n, err="TypeError: x", event="error", t0=1000):
    return [{"ts": t0 + i, "event": event, "error": err} for i in range(n)]


def test_backoff_exact_values():
    assert [DL.backoff_s(n) for n in range(1, 9)] == [10, 20, 40, 80, 160, 300, 300, 300]


def test_crash_loop_five_identical():
    assert DL.crash_loop(_ev(5), 0, 1010)[2] == 5
    assert DL.crash_loop(_ev(4), 0, 1010) is None


def test_crash_loop_breaks():
    assert DL.crash_loop(_ev(3) + _ev(1, err="other", t0=1003) + _ev(3, t0=1004), 0, 1010) is None
    assert DL.crash_loop(_ev(4) + [{"ts": 1004, "event": "deliver", "ok": True}] + _ev(4, t0=1005), 0, 1010) is None
    assert DL.crash_loop(_ev(8), 1005, 1010) is None
    assert DL.crash_loop(_ev(5), 0, 5000) is None
    assert DL.crash_loop(_ev(5, event="poll_error"), 0, 1010)[0] == "poll_error"


@pytest.fixture
def pend(tmp_path, hx):
    rep = hx.make_replica(tmp_path / "bus.sqlite3")
    room = tmp_path / "pend-room"
    (room / "journal").mkdir(parents=True)
    return rep, room


def test_operator_is_a_sender(hx):
    assert DL.SENDERS == (hx.HUMAN, "owner")


def test_evaluate_stuck_thresholds(pend, hx, tmp_path):
    rep, room = pend
    addr = hx.room_addr("gemini")
    now = time.time()
    hx.put_message(rep, "m1", hx.HUMAN, addr, age_s=200)
    assert DL.beacon(room, 0)
    pid = json.load(open(room / "journal" / "health.json"))["pid"]
    iss = DL.evaluate(str(room), addr, str(rep), pid, now - 1000, now)
    assert iss and iss["kind"] == "stuck_message" and iss["ids"] == ["m1"] and iss["oldest_age_s"] >= 200
    rep2 = hx.make_replica(tmp_path / "bus2.sqlite3")
    room2 = tmp_path / "room2"
    (room2 / "journal").mkdir(parents=True)
    hx.put_message(rep2, "m2", hx.HUMAN, addr, age_s=60)
    DL.beacon(room2, 0)
    assert DL.evaluate(str(room2), addr, str(rep2), os.getpid(), now - 1000, now) is None
    DL.beacon(room, 600)
    assert DL.evaluate(str(room), addr, str(rep), pid, now - 1000, now) is None


def test_evaluate_other_sender_is_not_pending(pend, hx):
    rep, room = pend
    addr = hx.room_addr("gemini")
    hx.put_message(rep, "m1", "human-someone-else", addr, age_s=500)
    DL.beacon(room, 0)
    now = time.time()
    assert DL.evaluate(str(room), addr, str(rep), os.getpid(), now - 1000, now) is None


def test_evaluate_acked_by_waker_but_replica_lags(pend, hx):
    rep, room = pend
    addr = hx.room_addr("gemini")
    now = time.time()
    hx.put_message(rep, "m1", hx.HUMAN, addr, age_s=500)
    hx.put_message(rep, "m2", hx.HUMAN, addr, age_s=400)
    DL.beacon(room, 0)
    (room / "journal" / "wake.jsonl").write_text(
        json.dumps({"ts": int(now - 300), "event": "ack", "id": "m1", "ok": True}) + "\n"
        + json.dumps({"ts": int(now - 200), "event": "ack", "id": "m2", "ok": False}) + "\n", encoding="utf-8")
    iss = DL.evaluate(str(room), addr, str(rep), os.getpid(), now - 1000, now)
    assert iss and iss["kind"] == "stuck_message" and iss["ids"] == ["m2"]
    (room / "journal" / "wake.jsonl").write_text(
        json.dumps({"ts": int(now - 300), "event": "woken", "id": "m2", "ack": True}) + "\n"
        + json.dumps({"ts": int(now - 300), "event": "ack", "id": "m1", "ok": True}) + "\n", encoding="utf-8")
    assert DL.evaluate(str(room), addr, str(rep), os.getpid(), now - 1000, now) is None


def test_evaluate_hung_and_pid(pend):
    rep, room = pend
    now = time.time()
    h = room / "journal" / "health.json"
    h.write_text(json.dumps({"pid": 111, "ts": now - 400, "busy_until": 0}))
    assert DL.evaluate(str(room), "a", str(rep), 111, now - 1000, now)["kind"] == "hung_loop"
    assert DL.evaluate(str(room), "a", str(rep), 222, now - 1000, now)["kind"] == "hung_loop"
    h.write_text(json.dumps({"pid": 111, "ts": now - 400, "busy_until": now + 60}))
    assert DL.evaluate(str(room), "a", str(rep), 111, now - 1000, now) is None
    h.write_text(json.dumps({"pid": 111, "ts": now - 5, "busy_until": 0}))
    assert DL.evaluate(str(room), "a", str(rep), 111, now - 1000, now) is None


def test_evaluate_crash_loop_from_journal(pend):
    rep, room = pend
    now = time.time()
    rows = [{"ts": int(now - 20 + i), "event": "error", "error": "TypeError: argument of type 'NoneType' is not iterable"} for i in range(5)]
    (room / "journal" / "wake.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")
    DL.beacon(room, 0)
    iss = DL.evaluate(str(room), "a", str(rep), os.getpid(), now - 60, now)
    assert iss and iss["kind"] == "crash_loop" and iss["detail"].startswith("5 x error")
    assert DL.evaluate(str(room), "a", str(rep), os.getpid(), now - 5, now) is None


def test_oldest_pending_unreadable(tmp_path):
    assert DL.oldest_pending(str(tmp_path / "nope.sqlite3"), "a") is None
    bad = tmp_path / "bad.sqlite3"
    bad.write_bytes(b"not a database \xff\xfe" * 50)
    assert DL.oldest_pending(str(bad), "a") is None


def test_healer_policy():
    restarts, alerts, notices = [], [], []
    h = DL.Healer("t", restarts.append, alerts.append, lambda i: (notices.append(i), True)[1], max_restarts=3, notice_after_s=300)
    iss = {"kind": "crash_loop", "detail": "d", "ids": ["m1"], "oldest_age_s": 100}
    assert h.observe(iss, 0) == "restart" and len(restarts) == 1
    assert h.observe(iss, 10) == "alert"
    assert len(restarts) == 1 and sum(a.get("severity") == "crit" for a in alerts) == 1
    assert h.observe(dict(iss, oldest_age_s=350), 20) == "notice" and len(notices) == 1
    assert h.observe(dict(iss, oldest_age_s=360), 30) == "wait" and len(notices) == 1
    assert h.observe(iss, 61) == "restart" and len(restarts) == 2
    assert h.observe(iss, 61 + 119) == "wait" and len(restarts) == 2
    assert h.observe(iss, 61 + 120) == "restart" and len(restarts) == 3
    assert h.observe(iss, 61 + 120 + 10000) == "wait" and len(restarts) == 3
    assert sum(a.get("severity") == "crit" for a in alerts) == 1
    assert h.observe(None, 20000) == "wait" and h.inc is not None and len(restarts) == 3
    assert h.observe(None, 20000 + 299) == "wait"
    assert h.observe(None, 20000 + 300) == "recovered" and alerts[-1]["kind"] == "recovered" and alerts[-1]["restarts"] == 3
    assert h.observe(None, 20301) == "ok"


def test_healer_transient_none_keeps_cap():
    restarts, alerts = [], []
    h = DL.Healer("t", restarts.append, alerts.append, max_restarts=3, recover_s=60)
    iss = {"kind": "crash_loop", "detail": "d", "ids": [], "oldest_age_s": 0}
    assert h.observe(iss, 0) == "restart" and len(restarts) == 1
    assert h.observe(None, 10) == "wait" and h.inc["restarts"] == 1
    assert h.observe(None, 69) == "wait"
    assert h.observe(iss, 70) == "restart" and len(restarts) == 2 and h.inc["restarts"] == 2
    assert h.inc.get("healthy_since") is None
    assert h.observe(iss, 70 + 10000) == "restart" and len(restarts) == 3
    assert h.observe(iss, 70 + 20000) == "wait" and len(restarts) == 3
    assert h.observe(None, 40000) == "wait"
    assert h.observe(None, 40000 + 60) == "recovered" and alerts[-1]["restarts"] == 3


def test_beacon_and_tail(tmp_path):
    room = tmp_path / "room"
    (room / "journal").mkdir(parents=True)
    assert DL.beacon(room, 30)
    b = DL.read_beacon(room)
    assert b["pid"] == os.getpid() and b["busy_until"] > time.time() + 20
    (room / "journal" / "wake.jsonl").write_bytes(b'{"a":1}\n\xff\xfe\x80\n{"b":2}\n[1,2]\n{"c"')
    assert [list(e)[0] for e in DL.tail_events(str(room))] == ["a", "b"]
    assert DL.tail_events(str(tmp_path)) == []


def test_agent_argv_and_clean_text():
    assert DL.agent_argv("x/a.py", ["-p", "q"], "PY") == ["PY", "-B", "x/a.py", "-p", "q"]
    assert DL.agent_argv("bin/agent.exe", ["-p", "q"], "PY") == ["bin/agent.exe", "-p", "q"]
    assert DL.clean_text("Привет�\x00\x07 мир\n") == "Привет мир"
    assert DL.clean_text(b"\xff\xfe\x80\x00") == "" and DL.clean_text(None) == "" and DL.clean_text("   ") == ""
    assert len(DL.clean_text("а" * 9000)) == 6000


def test_decode_bytes_none_safe():
    assert DL.decode_bytes(None) == "" and DL.decode_bytes("x") == "x" and DL.decode_bytes(bytearray(b"ab")) == "ab"
    assert DL.decode_bytes(b"\xff\x80").count("�") == 2
    assert DL.decode_bytes(123) == ""


def test_strip_service_notes_keeps_answer():
    text = "Тема: Кольцо\nПорт 3 без линка.\n\nОтправка ответа в комнату была отклонена, повторяю."
    out, n = DL.strip_service_notes(text)
    assert n == 1 and out == "Тема: Кольцо\nПорт 3 без линка."


def test_send_notice_dedupe(tmp_path, hx):
    room = stub_room(tmp_path)
    rt = str(room / "room_tool.py")
    assert DL.send_notice(str(room), sys.executable, rt)[0]
    assert DL.send_notice(str(room), sys.executable, rt)[1].startswith("suppressed")
    sends = [c for c in calls(room) if c["op"] == "send"]
    assert len(sends) == 1 and sends[0]["args"]["to"] == hx.HUMAN and "недоступен" in sends[0]["args"]["body"]
    assert DL.send_notice(str(room), sys.executable, rt, force=True)[0]
    assert len([c for c in calls(room) if c["op"] == "send"]) == 2


def test_ack_heartbeat_cp866_and_failures(tmp_path):
    room = stub_room(tmp_path, {"cp866": True, "fail_ops": {"ack": 1}})
    rt = str(room / "room_tool.py")
    assert DL.ack_message(str(room), sys.executable, rt, "m-1") is False
    assert DL.ack_message(str(room), sys.executable, rt, "m-1") is True
    assert DL.send_heartbeat(str(room), sys.executable, rt, "grok", "ready", "d") is True
    hb = [c for c in calls(room) if c["op"] == "heartbeat"]
    assert hb and hb[0]["args"]["vendor"] == "grok" and hb[0]["args"]["state"] == "ready"
    assert DL.ack_message(str(room), str(tmp_path / "no-python"), rt, "m-2") is False


def test_room_call_failure_is_false(tmp_path, hx):
    room = stub_room(tmp_path, {"fail_ops": {"send": 5}})
    ok, info = DL.room_call(str(room), sys.executable, str(room / "room_tool.py"), "send", "x1", {"to": hx.HUMAN, "body": "t"})
    assert ok is False and "stub-fail" in info


def test_topics_lock_retries_permission_error(tmp_path, monkeypatch, hx):
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("HUMANX_SHARED_DIR", str(shared))
    HT = hx.load_module("humanx_topics_lock_t", hx.RESOURCES / "client" / "humanx_topics.py")
    assert os.path.basename(HT.FILE) == "operator-topics.json"
    real_open = os.open
    state = {"n": 0}

    def flaky(path, flags, *a, **k):
        if path == HT.LOCK and (flags & os.O_EXCL):
            state["n"] += 1
            if state["n"] == 1:
                raise PermissionError(13, "Permission denied", path)
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", flaky)
    r = HT.put(upsert=[{"id": "00000001", "topic": "Тема", "status": "open", "state": "x", "last": []}], vendor="grok")
    monkeypatch.setattr(os, "open", real_open)
    assert r["ok"] and r["rev"] == 1 and state["n"] == 2
    assert not os.path.exists(HT.LOCK)
    assert HT.get()["topics"][0]["topic"] == "Тема"
