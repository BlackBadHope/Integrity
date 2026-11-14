"""Read-only gateway: caller checks, SQL and switch whitelists, Integrity snapshot reads. No switch, database or ssh is contacted."""
import io
import json
import sqlite3
import struct

import pytest


class FakeConn:
    def __init__(self, uid, line):
        self.uid, self._in, self.out = uid, io.BytesIO(line), b""

    def getsockopt(self, level, opt, size):
        return struct.pack("3i", 4242, self.uid, 4242)

    def makefile(self, mode, *a, **k):
        return self._in

    def sendall(self, b):
        self.out += bytes(b)

    def settimeout(self, t):
        pass


@pytest.fixture
def gw(gateway, monkeypatch):
    logged = []
    monkeypatch.setattr(gateway, "log", logged.append)
    gateway.logged = logged
    return gateway


def ask(gw, uid, req):
    conn = FakeConn(uid, (json.dumps(req) + "\n").encode())
    gw.H(conn, "", None)
    return json.loads(conn.out.decode("utf-8"))


def test_only_the_bus_gateway_and_room_vendors_may_call(gw, hx):
    assert ask(gw, hx.OTHER_UID, {"vendor": "claude", "op": "sql", "args": {"query": "SELECT 1"}})["error"] == "only the bus gateway may call"
    assert "only for the HumanX room Arbiters" in ask(gw, hx.GW_UID, {"vendor": "outsider", "op": "sql", "args": {}})["error"]
    assert ask(gw, hx.GW_UID, {"vendor": "claude", "op": "write", "args": {}})["error"] == "ops: sql | integrity | switch"
    assert ask(gw, hx.GW_UID, {"vendor": "claude", "op": "storm-read", "args": {"minutes": 10, "lines": 100}})["ok"] is False
    assert all("req_sha256" in r and "query" not in json.dumps(r) for r in gw.logged)


@pytest.mark.parametrize("sql", ["DROP TABLE users", "DELETE FROM users", "UPDATE users SET a=1", "SELECT 1; DROP TABLE users", "SELECT 1 -- x",
                                 "SELECT * FROM users INTO OUTFILE '/tmp/x'", "SELECT SLEEP(5)", "SELECT 1 FOR UPDATE",
                                 "SELECT 'a\\' OR 1", "", "INSERT INTO t VALUES (1)", "CALL p()", "SELECT /* c */ 1"])
def test_sql_refuses_anything_not_read_only(gw, sql, monkeypatch):
    s, err = gw.check_sql(sql)
    assert s is None and err

    def no_client(*args, **kwargs):   # the database is reached only through the client process
        raise AssertionError("the database client was started for a refused query")

    monkeypatch.setattr(gw.subprocess, "run", no_client)
    r = gw.op_sql({"query": sql})
    assert r["ok"] is False and r["error"].startswith("Отказ шлюза") and "rows_tsv" not in r


def test_sql_accepts_plain_reads_and_literal_marks(gw):
    assert gw.check_sql("SELECT id FROM users WHERE name = 'a; b -- c #'")[0]
    assert gw.check_sql("show tables")[0] == "show tables"
    assert gw.op_sql({"db": "bad name;", "query": "SELECT 1"})["error"] == "Отказ шлюза: неверное имя базы"


@pytest.mark.parametrize("args, text", [
    ({"ip": "not-an-ip", "cmds": ["show switch"]}, "нужен ip"),
    ({"ip": "192.0.2.77", "cmds": ["show switch"]}, "не из сети управления"),
    ({"ip": "198.51.100.5", "cmds": []}, "от 1 до 4"),
    ({"ip": "198.51.100.5", "cmds": ["show switch"] * 5}, "от 1 до 4"),
    ({"ip": "198.51.100.5", "cmds": ["config stp ports 1 state disable"]}, "только команды чтения"),
    ({"ip": "198.51.100.5", "cmds": ["show config current_config"]}, "только команды чтения"),
    ({"ip": "198.51.100.5", "cmds": ["show account"]}, "только команды чтения"),
    ({"ip": "198.51.100.5", "cmds": ["show switch", "reboot"]}, "только команды чтения"),
])
def test_switch_refusals_happen_before_any_session(gw, args, text):
    r = gw.op_switch(args)
    assert r["ok"] is False and text in r["error"]


def test_web_screens_have_narrow_rights(gw, hx, tmp_path, monkeypatch):
    cmds = ["show ports description", "show stp ports", "show stp", "show erps"]
    assert gw.web_rings_allowed(hx.WEB_UID, "web-rings", "switch", {"ip": "192.0.2.1", "cmds": cmds})
    assert not gw.web_rings_allowed(hx.WEB_UID, "web-rings", "switch", {"ip": "198.51.100.5", "cmds": cmds})
    assert not gw.web_rings_allowed(hx.WEB_UID, "web-rings", "switch", {"ip": "192.0.2.1", "cmds": cmds[:3] + ["show log"]})
    assert not gw.web_rings_allowed(hx.OTHER_UID, "web-rings", "switch", {"ip": "192.0.2.1", "cmds": cmds})
    assert not gw.web_rings_allowed(hx.WEB_UID, "web-rings", "switch", {"ip": "192.0.2.1", "cmds": cmds, "fresh": True})
    assert gw.web_storm_allowed(hx.WEB_UID, "web-storm", "storm-read", {"minutes": 120, "lines": 3000})
    assert not gw.web_storm_allowed(hx.WEB_UID, "web-storm", "storm-read", {"minutes": 120, "lines": 3001})
    assert not gw.web_storm_allowed(hx.WEB_UID, "web-storm", "storm-read", {"minutes": "120", "lines": 100})
    off = tmp_path / "web-rings.off"
    off.write_text("", encoding="utf-8")
    monkeypatch.setattr(gw, "WEB_OFF", str(off))
    assert not gw.web_rings_allowed(hx.WEB_UID, "web-rings", "switch", {"ip": "192.0.2.1", "cmds": cmds})


def test_integrity_snapshot_reads(gw, tmp_path, monkeypatch):
    seed = tmp_path / "seed.sqlite3"
    db = sqlite3.connect(str(seed))
    db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, ts_utc TEXT, actor TEXT, action TEXT, summary TEXT, details TEXT, tags TEXT)")
    db.executemany("INSERT INTO events(ts_utc, actor, action, summary, details, tags) VALUES(?,?,?,?,?,?)",
                   [("2026-01-01T00:00:00Z", "agent-a", "note", "кольцо 100 замкнуто", "d", "ring"),
                    ("2026-01-01T00:01:00Z", "agent-b", "note", "другое", "d", "misc")])
    db.commit()
    db.close()
    monkeypatch.setattr(gw, "SEED", str(seed))
    assert [e["id"] for e in gw.op_integrity({"q": "recent", "n": 5})["events"]] == [2, 1]
    assert [e["id"] for e in gw.op_integrity({"q": "search", "text": "кольцо"})["events"]] == [1]
    assert gw.op_integrity({"q": "show", "id": 2})["event"]["tags"] == "misc"
    assert gw.op_integrity({"q": "stats"})["events"] == 2
    assert gw.op_integrity({"q": "drop"})["ok"] is False
    assert gw.op_integrity({"q": "search"})["error"] == "нужен text"
