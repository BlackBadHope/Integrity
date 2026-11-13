"""room_tool validation (adapted from the pilot fix suites): checks run before anything reaches the bus."""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import uuid

import pytest

T = "Тема: Проверка\nтекст ответа"


@pytest.fixture
def room(tmp_path, hx, monkeypatch):
    d = hx.new_room(tmp_path, "grok")
    rep = hx.make_replica(tmp_path / "rep.sqlite3")
    me, other = hx.room_addr("grok"), hx.room_addr("gemini")
    ids = {k: str(uuid.uuid4()) for k in ("old", "mid", "last", "other", "arb")}
    hx.put_message(rep, ids["old"], hx.HUMAN, me, status="replied")
    hx.put_message(rep, ids["mid"], hx.HUMAN, me, status="acked")
    hx.put_message(rep, ids["last"], hx.HUMAN, me, status="pending")
    hx.put_message(rep, ids["other"], hx.HUMAN, other)
    hx.put_message(rep, ids["arb"], me, hx.HUMAN)
    rt = hx.load_module("rt_" + uuid.uuid4().hex[:8], d / "room_tool.py")
    rt.REPLICA = str(rep)
    sent = []
    rt.bus = lambda op, args: (sent.append((op, args)) or {"ok": True})
    rt.bus_ro = lambda op, args: (sent.append((op, args)) or {"ok": True})

    def run(op, a=None, raw=None, name="t.json"):
        p = d / "work" / name
        if raw is not None:
            p.write_bytes(raw)
        elif a is not None:
            p.write_text(json.dumps(a, ensure_ascii=False), encoding="utf-8")
        sent.clear()
        o, e = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
                rt.main(["room_tool.py", op, "work/" + name])
        except SystemExit as x:
            return "REJECT", str(x.code)
        return "SENT", json.loads(o.getvalue().strip().splitlines()[-1])

    return {"dir": d, "rt": rt, "run": run, "sent": sent, "ids": ids, "me": me}


def test_identity_comes_from_configuration(room, hx):
    assert room["rt"].ME == hx.room_addr("grok")
    assert set(room["rt"].HOSTS) == {"node-a", "core"} and room["rt"].JUMP == "jump-alias"


def test_reply_cases(room, hx):
    run, ids = room["run"], room["ids"]
    r = run("reply", {"reply_to": ids["old"], "body": T})
    assert r[0] == "SENT" and any("более новые письма" in w for w in r[1]["warnings"])
    assert room["sent"][0][1]["to"] == hx.HUMAN
    assert run("reply", {"reply_to": ids["last"], "body": T}) == ("SENT", {"ok": True})
    assert run("reply", {"body": T})[0] == "REJECT"
    assert run("reply", {"reply_to": "deadbeef-0000-0000-0000-000000000000", "body": T})[0] == "REJECT"
    assert run("reply", {"reply_to": "abc; rm", "body": T})[0] == "REJECT"
    assert "это письмо не от" in run("reply", {"reply_to": ids["other"], "body": T})[1]
    assert run("reply", {"reply_to": ids["arb"], "body": T})[0] == "REJECT"
    assert run("reply", {"reply_to": ids["last"], "body": "просто текст"})[0] == "REJECT"
    assert run("reply", {"reply_to": ids["last"], "body": "  \n "})[0] == "REJECT"


def test_body_limits_and_encoding_guards(room):
    run, last = room["run"], room["ids"]["last"]
    head = "Тема: x\n"
    assert "лимита ядра 32768" in run("reply", {"reply_to": last, "body": head + "я" * 17000})[1]
    assert run("reply", {"reply_to": last, "body": head + "a" * (32768 - len(head.encode()))})[0] == "SENT"
    assert run("reply", {"reply_to": last, "body": head + "a" * (32769 - len(head.encode()))})[0] == "REJECT"
    assert "мойибаке" in run("reply", {"reply_to": last, "body": "?????: ?????\n" + "??? " * 100})[1]
    assert run("reply", {"reply_to": last, "body": "Тема: Кольцо\n" + "?????? ?????? ?????? ?????"})[0] == "REJECT"
    assert "U+FFFD" in run("reply", {"reply_to": last, "body": head + "текст ��"})[1]
    assert run("reply", {"reply_to": last, "body": "Тема: Вопрос\nКакой порт? Какой свич? Когда?"})[0] == "SENT"
    assert run("reply", {"reply_to": last, "body": "Тема: Вопросы\n" + "Why is this happening on the ring port again? " * 12 + "и да"})[0] == "SENT"


def test_send_and_escalate_targets(room, hx):
    run = room["run"]
    assert run("send", {"to": hx.HUMAN, "body": T})[0] == "SENT"
    assert run("send", {"to": hx.room_addr("codex"), "body": T})[0] == "REJECT"
    assert run("send", {"to": "owner", "body": "просьба передать"})[0] == "SENT"
    assert run("escalate", {"reply_to": room["ids"]["last"], "body": "нужно изменение"})[0] == "SENT"
    payload = room["sent"][0][1]
    assert payload["to"] == "owner" and payload["reply_to"] is None
    assert run("escalate", {"body": ""})[0] == "REJECT"


def test_ring_change_needs_model_rollback_check_and_loop_warning(room):
    run, last = room["run"], room["ids"]["last"]
    assert run("reply", {"reply_to": last, "body": "Тема: STP\nconfig stp ports 1 state disable"})[0] == "REJECT"
    full = ("Тема: STP\nМодель: DES-3028\nconfig stp ports 1 state disable\nОткат: config stp ports 1 state enable\n"
            "Проверка: show stp ports 1\nОшибка в точке блокировки даёт петлю.")
    assert run("reply", {"reply_to": last, "body": full})[0] == "SENT"


def test_switch_and_host_limits(room):
    run = room["run"]
    assert run("switch", {"ip": "198.51.100.5", "cmds": ["show switch"] * 5})[0] == "REJECT"
    assert run("switch", {"ip": "198.51.100.5", "cmds": ["show switch"] * 4})[0] == "SENT"
    assert len(room["sent"][0][1]["cmds"]) == 4
    rt = room["rt"]
    assert rt.host_read({"host": "core", "op": "journal", "args": ["a", "b", "c", "d"]})["ok"] is False
    assert rt.host_read({"host": "not-listed", "op": "summary"})["ok"] is False
    assert rt.host_read({"host": "core", "op": "status", "args": ["x;rm"]})["ok"] is False


def test_host_read_results(room, monkeypatch):
    rt = room["rt"]
    seen = []

    class P:
        def __init__(self, rc, out):
            self.returncode, self.stdout, self.stderr = rc, out, b""

    def fake(rc, out):
        def run(argv, **kw):
            seen.append(argv)
            return P(rc, out)
        return run

    monkeypatch.setattr(rt.subprocess, "run", fake(255, b""))
    assert "access gap" in rt.host_read({"host": "node-a", "op": "summary"})["error"]
    assert any(a.endswith("jump-alias -W %h:%p") for a in seen[-1])
    monkeypatch.setattr(rt.subprocess, "run", fake(0, b"active"))
    assert rt.host_read({"host": "core", "op": "status", "args": ["unit-a"]})["ok"] is True


def test_argument_file_encodings(room):
    run, last = room["run"], room["ids"]["last"]
    doc = json.dumps({"reply_to": last, "body": T}, ensure_ascii=False)
    assert run("reply", raw=doc.encode("cp1251"))[0] == "REJECT"
    assert run("reply", raw=b"\xff\xfe" + doc.encode("utf-16-le"))[0] == "REJECT"
    assert run("reply", raw=b"\xef\xbb\xbf" + doc.encode("utf-8"))[0] == "SENT"
    assert run("reply", raw=b"{not json")[0] == "REJECT"
    with pytest.raises(SystemExit):
        room["rt"].main(["room_tool.py", "reply", "work/nonexist.json"])
    with pytest.raises(SystemExit):
        room["rt"].load_args("../room.json")


def test_bus_transport_errors_are_caught(tmp_path, hx, monkeypatch):
    d = hx.new_room(tmp_path, "claude")
    rt = hx.load_module("rt_bus_" + uuid.uuid4().hex[:8], d / "room_tool.py")

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("ssh", 60)

    def missing(*a, **k):
        raise FileNotFoundError("ssh")

    for boom, text in ((timeout, "bus timeout"), (missing, "bus unreachable")):
        monkeypatch.setattr(rt.subprocess, "run", boom)
        with pytest.raises(SystemExit) as e:
            rt.bus("send", {})
        assert text in str(e.value.code)


def test_journal_hash_chain_and_rotation(tmp_path, hx, monkeypatch):
    monkeypatch.setenv("ROOM_JOURNAL_MAX", "3000")
    d = hx.new_room(tmp_path, "codex")
    rt = hx.load_module("rt_j_" + uuid.uuid4().hex[:8], d / "room_tool.py")
    for i in range(40):
        rt.journal({"op": "heartbeat", "n": i, "pad": "x" * 60})
    j = d / "journal"
    assert (j / "room.jsonl.1").exists()
    rows = []
    for name in sorted((p.name for p in j.glob("room.jsonl.*")), key=lambda n: -int(n.rsplit(".", 1)[1])) + ["room.jsonl"]:
        rows += [json.loads(x) for x in (j / name).read_text(encoding="utf-8").splitlines()]
    assert [r["n"] for r in rows] == list(range(40))
    prev = "0" * 64
    for r in rows:
        assert r["prev"] == prev and r["by"] == hx.room_addr("codex")
        body = {k: v for k, v in r.items() if k != "hash"}
        assert hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest() == r["hash"]
        prev = r["hash"]


@pytest.mark.parametrize("body, marker", [("?" * 30, "мойибаке"), ("я" * 16385, "лимита ядра 32768"),
                                          ("Тема: тест �", "U+FFFD"), ("я" * 16384, "bus unreachable"),
                                          ("Тема: проверка\nПривет, это нормальный текст.", "bus unreachable")])
def test_room_tool_process_guards(tmp_path, hx, body, marker):
    """The real script in a fresh interpreter: guards answer before the bus; the valid text reaches a transport that cannot start."""
    d = hx.new_room(tmp_path, "gemini")
    (d / "work" / "a.json").write_text(json.dumps({"to": "owner", "body": body}, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, BUS_REPLICA=str(hx.make_replica(tmp_path / "r.sqlite3")), PYTHONUTF8="1")
    p = subprocess.run([sys.executable, "-B", str(d / "room_tool.py"), "send", "work/a.json"], cwd=str(d), capture_output=True,
                       timeout=60, env=env)
    out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    assert marker in out
    if marker != "bus unreachable":
        assert "bus unreachable" not in out and not (d / "journal" / "room.jsonl").exists()
