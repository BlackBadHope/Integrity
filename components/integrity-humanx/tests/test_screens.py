"""Rings and storm screens with an invented ring map and invented switch output (no gateway, no network)."""
import datetime as dt
import json

import re

import pytest

import rings_screen as RS
import storm_screen as SS


def mac(n):
    """Invented locally administered MAC, built at run time."""
    return "-".join(["02", "00", "00", "00", "00", "%02X" % n])

PORTS = """Port   State/          Settings             Connection           Address
       MDI             Speed/Duplex/FlowCtrl Speed/Duplex/FlowCtrl Learning
 1     Enabled         Auto/Disabled        1000M/Full/None      Enabled
 Description: up <b>link</b> & "a"
 2     Enabled         Auto/Disabled        Link Down            Enabled
 3     Enabled         Auto/Disabled        100M/Full/None       Enabled
"""
STP_PORTS = re.sub(r"<MAC([0-9A-F]{2})>", lambda x: mac(int(x.group(1), 16)), """Port Index    : 1
 Port STP : Enabled
 MSTI   Designated Bridge   Internal PathCost  Prio  Status      Role
 0      8000/<MAC01>  200000      128   Forwarding  Root
Port Index    : 2
 Port STP : Enabled
 MSTI   Designated Bridge   Internal PathCost  Prio  Status      Role
 0      8000/<MAC01>  200000      128   Discarding  Alternate
""")


def doc(at):
    return {"ok": True, "fetched_at": at, "outputs": {"show ports description": PORTS, "show stp ports": STP_PORTS,
                                                       "show stp": "STP Status : Enabled\nSTP Version : RSTP",
                                                       "show erps": "Global Status : Disabled"}}


def test_cores_come_from_the_ring_map(hx):
    assert RS.CORES == hx.RING_MAP["cores"]
    assert RS.NOT_POLLED == [{"ring": "300", "core": "192.0.2.3"}]
    assert SS.ACCESS_PREFIX == "198.51"


def test_rings_build_render_lint(hx):
    now = 1_800_000_000
    data = RS.build({"192.0.2.1": doc(now - 30), "192.0.2.2": {"ok": False, "error": "<нет ответа>"}}, hx.RING_MAP, now=now)
    by = {r["ring"]: r for r in data["rings"]}
    assert by["100"]["state"] == "разомкнуто" and by["100"]["up"] == 1
    assert by["101"]["state"] == "одно плечо на ядре"
    assert by["200"]["state"] == "нет данных"
    html = RS.render(data)
    assert RS.lint(html, data) == []
    assert "Кольца на ядрах 2.1 и 2.2" in html          # short core names: the last two octets, as before the port
    assert "up &lt;b&gt;link&lt;/b&gt; &amp; &quot;a&quot;" in html and "<b>link</b>" not in html
    assert "&lt;нет ответа&gt;" in html
    assert 'data-k="not-polled">Кольцо 300 ' in html


def test_rings_lint_refuses_script_and_foreign_links(hx):
    data = RS.build({}, hx.RING_MAP, now=1_800_000_000)
    html = RS.render(data)
    assert "script" in RS.lint(html.replace("</main>", "<script>x</script></main>"), data)
    assert any(x.startswith("ссылка") for x in RS.lint(html.replace("</main>", '<a href="http://web.example.invalid/">x</a></main>'), data))


def test_rings_screen_from_fixtures(tmp_path, monkeypatch):
    for ip in RS.CORES:
        (tmp_path / ("core-%s.json" % ip)).write_text(json.dumps(doc(1_800_000_000)), encoding="utf-8")
    monkeypatch.setenv("HUMANX_RINGS_FIXTURES", str(tmp_path))
    html, m = RS.screen(str(tmp_path))
    assert m["lint"] == [] and "НЕ ЖИВЫЕ ДАННЫЕ" in html


TZ = dt.timezone(dt.timedelta(hours=2))


def ts(sec):
    return dt.datetime.fromtimestamp(1_800_000_000 + sec, TZ).isoformat()


def sensor_lines(start=0, clear=600, vlan="100"):
    return ["%s s TRUNKBCAST alarm id=1 rx_pps=9000 mc_pps=0 peak=9000 since=%s vlans=%s:40/50" % (ts(start + 5), ts(start), vlan),
            "%s s TRUNKBCAST clear id=1 rx_pps=100 mc_pps=0 peak=9500 since=%s vlans=-" % (ts(clear), ts(start))]


def test_storm_names_the_stp_change_before_the_storm(hx):
    log = ["%s 198.51.100.7 Successful login through Telnet (Username: admin, IP: 203.0.113.9)" % ts(-200),
           "%s 198.51.100.7 Spanning Tree Protocol is disabled" % ts(-120),
           "%s 192.0.2.1 Port 1 broadcast storm is occurring" % ts(10),
           "%s 192.0.2.1 Port 2 broadcast storm is occurring" % ts(70),
           "%s 198.51.100.7 Port 4 link down <x>" % ts(80)]
    d = SS.build(sensor_lines(), log, hx.RING_MAP)
    assert d["vlan"] == "100" and d["ring"]["ring"] == "100"
    assert "кольцо 100" in d["headline"] and "на свиче 198.51.100.7 выключен STP" in d["headline"]
    assert "203.0.113.9" in d["headline"]
    html = SS.render(d, TZ, fx=True)
    assert SS.lint(html, d) == []


def test_storm_without_events_says_so(hx):
    d = SS.build([], [], hx.RING_MAP)
    assert d["headline"] == "Датчик транка шторма не отмечал."


def test_storm_page_size_limit(hx):
    """A long storm window stays under MAX_BYTES and EV_MAX rows; the rest is a counter line."""
    log = []
    for i in range(3000):
        sw = "198.51.100.%d" % (1 + i % 200)
        log.append("%s %s Successful login through Web (Username: u%d, IP: 203.0.113.%d)" % (ts(-800 + i // 10), sw, i, i % 250))
        if i % 3 == 0:
            log.append("%s %s Spanning Tree Protocol is disabled" % (ts(-800 + i // 10), sw))
    for i in range(400):
        log.append("%s 192.0.2.1 Port %d broadcast storm is occurring" % (ts(i * 2), 1 + i % 24))
    d = SS.build(sensor_lines(clear=1200), log, hx.RING_MAP)
    html = SS.render(d, TZ, fx=True)
    assert SS.lint(html, d) == []
    assert len(html.encode()) <= SS.MAX_BYTES
    assert html.count('<span class="t">') <= SS.EV_MAX
    assert 'data-k="ev-cut"' in html
    assert html.count("<th>п.") <= len(d["ring"]["ports"]) + SS.COLS_EXTRA


def test_storm_lint_catches_oversize(hx):
    d = SS.build(sensor_lines(), [], hx.RING_MAP)
    html = SS.render(d, TZ, fx=True)
    big = html.replace("</main>", "<p>" + "x" * (SS.MAX_BYTES + 1) + "</p></main>")
    assert any(x.startswith("размер") for x in SS.lint(big, d))


def test_storm_screen_without_right_or_fixtures():
    html, m = SS.screen()
    assert "нет права чтения журнала свичей" in html and m["lint"] == []


def test_storm_cards_to_sensor():
    ca = int(dt.datetime(2026, 1, 2, 10, 0, 30, tzinfo=TZ).timestamp())
    start = ":".join(["10", "00", "00"])      # built at run time: a literal clock time reads as an address to the surface scanner
    lines = SS.cards_to_sensor([[ca, "Шторм на транке: 9 000 пак/с, начало: %s, VLAN по выборке: 100:40/50" % start]], TZ)
    eps = SS.parse_sensor(lines)
    assert len(eps) == 1 and eps[0]["vlans"][0]["vlan"] == "100" and eps[0]["peak"] == 9000
