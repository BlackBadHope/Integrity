"""Room web handlers in-process: a fake socket feeds raw HTTP, the bus is replaced by a function (no socket, no network)."""
import io
import json

import pytest

import humanx_web as W


class FakeConn:
    def __init__(self, raw):
        self._in = io.BytesIO(raw)
        self.out = b""

    def makefile(self, mode, *a, **k):
        return self._in

    def sendall(self, b):
        self.out += bytes(b)

    def settimeout(self, t):
        pass


def request(method, path, ip="192.0.2.40", body=b"", headers=None):
    h = {"Host": "web.example.invalid", "Content-Length": str(len(body))}
    h.update(headers or {})
    raw = ("%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n").encode() + body
    conn = FakeConn(raw)
    W.H(conn, (ip, 50000), None)
    head, _, payload = conn.out.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, head.decode("latin-1"), payload


@pytest.fixture
def bus(monkeypatch, hx, tmp_path):
    calls = []
    state = {"arbiter": {"arbiter": "codex", "address": hx.room_addr("codex"), "ts": 0}}

    def fake(op, args=None):
        calls.append((op, args))
        if op == "room-arbiter":
            return {"ok": True, "result": {"arbiter": state["arbiter"]}}
        if op == "vendor-cards":
            return {"ok": True, "result": {"cards": [{"vendor": "codex", "state": "<ready>"}]}}
        if op == "poll":
            return {"ok": True, "result": {"queue": []}}
        return {"ok": True, "result": {}}

    sent_f = tmp_path / "sent.jsonl"
    monkeypatch.setattr(W, "bus", fake)
    monkeypatch.setattr(W, "SENT_F", str(sent_f))
    monkeypatch.setattr(W, "REPL_F", str(tmp_path / "replies.jsonl"))
    monkeypatch.setattr(W, "ARB_LOG_F", str(tmp_path / "arbiter-switch.jsonl"))
    monkeypatch.setattr(W, "_cache", {"cards": None, "cards_ts": 0})
    return calls, state, sent_f


def test_page_only_for_allowed_addresses(bus, hx):
    status, head, page = request("GET", "/")
    assert status == 200 and "Content-Security-Policy" in head and "X-Frame-Options: DENY" in head
    text = page.decode("utf-8")
    assert "__HX_ROOM_PREFIX__" not in text and ".replace('room-%s-','Арбитр ')" % hx.OPERATOR in text
    assert request("GET", "/", ip="198.51.100.99")[0] == 403
    assert request("GET", "/nope")[0] == 404


def test_post_needs_csrf_header(bus):
    body = json.dumps({"body": "x", "page": W.PAGE_BUILD}).encode()
    assert request("POST", "/api/send", body=body)[0] == 403


def test_send_goes_to_current_arbiter_and_is_recorded(bus, hx):
    calls, state, sent_f = bus
    body = json.dumps({"body": "Тема? <b>порт</b>", "page": W.PAGE_BUILD, "maxr": True}).encode("utf-8")
    status, _, payload = request("POST", "/api/send", body=body, headers={"X-HumanX": "1"})
    assert status == 200 and json.loads(payload)["ok"] is True
    send = [a for op, a in calls if op == "send"][0]
    assert send["to"] == hx.room_addr("codex") and send["body"].endswith("\n" + W.MAXR_LINE)
    rec = json.loads(sent_f.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["body"] == "Тема? <b>порт</b>" and rec["maxr"] is True


def test_stale_page_and_empty_message_are_refused(bus):
    calls = bus[0]
    stale = json.dumps({"body": "x", "page": "old"}).encode()
    r = json.loads(request("POST", "/api/send", body=stale, headers={"X-HumanX": "1"})[2])
    assert r["ok"] is False and "Страница устарела" in r["error"]
    empty = json.dumps({"body": "  ", "page": W.PAGE_BUILD}).encode()
    assert json.loads(request("POST", "/api/send", body=empty, headers={"X-HumanX": "1"})[2])["error"] == "Пустое сообщение"
    assert not [c for c in calls if c[0] == "send"]


def test_state_api_is_json_and_marks_working(bus, hx):
    calls, state, sent_f = bus
    import time
    sent_f.write_text(json.dumps({"id": "00000000-0000-4000-8000-000000000001", "to": hx.room_addr("codex"),
                                  "body": "<script>x</script>", "ts": int(time.time()) - 5}) + "\n", encoding="utf-8")
    status, head, payload = request("GET", "/api/state")
    doc = json.loads(payload)
    assert status == 200 and "application/json" in head
    assert doc["chat"][0]["body"] == "<script>x</script>"           # the page inserts text with textContent, not as HTML
    assert doc["working"]["to"] == hx.room_addr("codex")


def test_rings_page_is_escaped_and_sandboxed(bus, tmp_path, monkeypatch):
    rs = W.RS
    for ip in rs.CORES:
        (tmp_path / ("core-%s.json" % ip)).write_text(json.dumps({"ok": True, "fetched_at": 1_800_000_000, "outputs": {
            "show ports description": " 1     Enabled         Auto/Disabled        1000M/Full/None      Enabled\n"
                                      " Description: <img src=x>\n",
            "show stp ports": "", "show stp": "", "show erps": ""}}), encoding="utf-8")
    monkeypatch.setenv("HUMANX_RINGS_FIXTURES", str(tmp_path))
    status, head, page = request("GET", "/rings")
    text = page.decode("utf-8")
    assert status == 200 and "sandbox" in head
    assert "&lt;img src=x&gt;" in text and "<img" not in text


def test_attachment_types_are_whitelisted(bus, tmp_path, monkeypatch):
    monkeypatch.setattr(W, "FILES_D", str(tmp_path / "files"))
    meta, err = W.file_save("../../a.exe", b"MZ")
    assert meta is None and ".exe" in err
    meta, err = W.file_save("dir\\shot.png", b"\x89PNG")
    assert err is None and meta["name"] == "shot.png" and W.file_meta(meta["id"])["size"] == 4
    assert W.file_meta("../etc") is None
