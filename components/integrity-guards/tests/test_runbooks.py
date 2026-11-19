"""Event-driven runbooks: triggers, the dispatcher and its install commands.

Every route here is invented and runs only the current Python interpreter. No model is
called: the agent adapters are a stub script that records the prompt it was given.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from integrity_guards import runbooks as rb
from integrity_guards import runbooks_cli

COMPONENT = Path(__file__).resolve().parents[1]
REPO = COMPONENT.parents[1]
PY = sys.executable


@pytest.fixture(autouse=True)
def _private_killswitch(tmp_path, monkeypatch):
    """Every test gets its own kill switch state; nothing touches the user's real one."""
    monkeypatch.setenv("INTEGRITY_KILLSWITCH_STATE", str(tmp_path / "ks" / "killswitch.json"))
    monkeypatch.setenv("INTEGRITY_KILLSWITCH_LOG", str(tmp_path / "ks" / "killswitch.log"))
    monkeypatch.delenv("INTEGRITY_KILLSWITCH_CONFIG", raising=False)
    monkeypatch.delenv("INTEGRITY_ROUTE_WRITE_GO", raising=False)
    monkeypatch.delenv("INTEGRITY_COMPILED_ROUTES", raising=False)
    monkeypatch.delenv("INTEGRITY_GUARDS_CONFIG", raising=False)


def read_route(tmp_path: Path) -> dict:
    return {
        "format": "uroboros-compiled-route/v1", "route_id": "example.node-read", "version": 1, "safety": "read",
        "summary": "Invented: reads the state of node {{name}}",
        "params": {"name": "[a-z][a-z0-9-]{0,30}"},
        "steps": [{"name": "read-node", "argv": [PY, "-c", "print('state of {{name}}: up')"],
                   "extract": {"state": r"state of \S+: (\w+)"}, "timeout_s": 20}],
        "timeout_s": 60,
    }


def write_route(tmp_path: Path) -> dict:
    marker = (tmp_path / "written.txt").as_posix()
    backup = (tmp_path / "backup.txt").as_posix()
    return {
        "format": "uroboros-compiled-route/v1", "route_id": "example.node-restart", "version": 1,
        "safety": "write", "summary": "Invented: restarts node {{name}}",
        "params": {"name": "[a-z][a-z0-9-]{0,30}"},
        "backup": [{"name": "backup", "argv": [PY, "-c", f"open({backup!r}, 'w').write('b')"]}],
        "steps": [{"name": "restart", "argv": [PY, "-c", f"open({marker!r}, 'w').write('{{{{name}}}}')"],
                   "writes": True}],
        "timeout_s": 60,
    }


def routes_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "compiled"
    folder.mkdir(exist_ok=True)
    for route in (read_route(tmp_path), write_route(tmp_path)):
        (folder / f"{route['route_id']}.json").write_text(json.dumps(route), encoding="utf-8")
    return folder


def config(tmp_path: Path, triggers: list[dict], **extra) -> dict:
    data = runbooks_cli.starter_config(str(routes_folder(tmp_path)))
    data.update({"enabled": True, "triggers": triggers})
    data["limits"].update(extra.pop("limits", {}))
    data.update(extra)
    return data


def file_trigger(tmp_path: Path, **extra) -> dict:
    trigger = {"trigger_id": "node-down", "source": {"kind": "file", "path": str(tmp_path / "app.log")},
               "match": r"node (?P<name>\S+) is down", "route_id": "example.node-read",
               "suppress_s": 600, "max_per_hour": 10}
    trigger.update(extra)
    return trigger


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def dispatcher(tmp_path: Path, cfg: dict, **kw) -> rb.Dispatcher:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return rb.Dispatcher(cfg, home, **kw)


def append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(text + "\n")


def kinds(d: rb.Dispatcher) -> list[str]:
    return [r["kind"] for r in d.journal.records()]


class TestDispatch:
    def test_a_log_line_runs_a_read_route_without_a_model(self, tmp_path):
        log = tmp_path / "app.log"
        append(log, "node old-node is down")  # written before the dispatcher started: not replayed
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]))
        assert d.poll_once() == []
        append(log, "unrelated line")
        append(log, "node edge-7 is down")
        [record] = d.poll_once()
        assert record["kind"] == "turn" and record["ok"] is True and record["model_turn"] is False
        assert record["adapter"] == "route" and record["params"] == {"name": "edge-7"}
        assert record["outputs"] == {"state": "up"}
        assert record["production_authority"] is False
        assert "edge-7 is down" not in json.dumps(d.journal.records())  # the raw line is kept as a hash only
        assert d.journal.verify() == (True, "1 records, chain intact")

    def test_a_stub_agent_adapter_gets_the_route_command_in_its_prompt(self, tmp_path):
        stub = tmp_path / "stub_agent.py"
        seen = tmp_path / "prompt.txt"
        stub.write_text(
            "import json, sys\n"
            f"open({seen.as_posix()!r}, 'w', encoding='utf-8').write(sys.argv[1])\n"
            "print(json.dumps({'result': 'route ran', 'total_cost_usd': 0.0012}))\n", encoding="utf-8")
        adapters = {"stub-agent": {"kind": "command", "vendor": "claude", "argv": [PY, str(stub), "{{prompt}}"],
                                   "timeout_s": 60}}
        cfg = config(tmp_path, [file_trigger(tmp_path, adapter="stub-agent", terms=["edge", "outage"])],
                     adapters=adapters)
        d = dispatcher(tmp_path, cfg)
        record = d.handle("node-down", "node edge-7 is down")
        assert record["kind"] == "turn" and record["ok"] and record["model_turn"] and record["vendor"] == "claude"
        prompt = seen.read_text(encoding="utf-8")
        assert "integrity-guards uroboros run example.node-read name=edge-7" in prompt
        assert "safety: read" in prompt and "outage" in prompt
        assert record["cost_usd"] == pytest.approx(0.0012)
        report = rb.spend_report(d.journal.records())
        assert report["by_adapter"]["stub-agent"]["model_turns"] == 1
        assert report["model_cost_usd"] == pytest.approx(0.0012)

    def test_a_write_route_becomes_a_proposal_and_never_runs(self, tmp_path, monkeypatch):
        # Even with an operator GO in the environment the dispatcher does not apply a write route.
        monkeypatch.setenv("INTEGRITY_ROUTE_WRITE_GO", "example.node-restart")
        notified = tmp_path / "notified.json"
        notify = {"argv": [PY, "-c", f"import sys; open({notified.as_posix()!r}, 'w').write(sys.stdin.read())"]}
        cfg = config(tmp_path, [file_trigger(tmp_path, route_id="example.node-restart")], notify=notify)
        d = dispatcher(tmp_path, cfg)
        record = d.handle("node-down", "node edge-7 is down")
        assert record["kind"] == "proposal"
        assert record["go_command"] == ("INTEGRITY_ROUTE_WRITE_GO=example.node-restart "
                                        "integrity-guards uroboros run example.node-restart name=edge-7 --apply")
        assert not (tmp_path / "written.txt").exists() and not (tmp_path / "backup.txt").exists()
        assert json.loads(notified.read_text(encoding="utf-8"))["kind"] == "proposal"
        assert kinds(d) == ["proposal", "notify"]

    @pytest.mark.parametrize("line", [
        "node $(touch${IFS}pwned) is down",
        "node edge;rm is down",
        "node EDGE is down",
        "node ../../etc is down",
        "node " + "a" * 250 + " is down",
    ])
    def test_a_bad_parameter_is_rejected_by_the_route_regex(self, tmp_path, line):
        calls = []
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]),
                       route_runner=lambda argv, timeout: calls.append(argv) or (0, "", ""))
        record = d.handle("node-down", line)
        assert record["kind"] == "rejected" and calls == []
        assert "params" not in record and record["line_sha256"]
        assert "pwned" not in json.dumps(d.journal.records())

    def test_dedup_suppresses_a_repeat_inside_the_window(self, tmp_path):
        clock = Clock()
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path, suppress_s=300)]), clock=clock)
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "turn"
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "suppressed"
        assert d.handle("node-down", "node edge-8 is down")["kind"] == "turn"  # another key
        clock.now += 301
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "turn"

    def test_the_hourly_limits_hold(self, tmp_path):
        clock = Clock()
        second = file_trigger(tmp_path, trigger_id="node-down-2", match=r"host (?P<name>\S+) lost")
        cfg = config(tmp_path, [file_trigger(tmp_path, max_per_hour=2), second], limits={"max_turns_per_hour": 3})
        d = dispatcher(tmp_path, cfg, clock=clock)
        got = [d.handle("node-down", f"node edge-{i} is down")["kind"] for i in range(3)]
        assert got == ["turn", "turn", "rate-limited"]
        assert d.handle("node-down-2", "host core-1 lost")["kind"] == "turn"
        assert d.handle("node-down-2", "host core-2 lost")["kind"] == "rate-limited"  # global 3 per hour
        clock.now += 3601
        assert d.handle("node-down", "node edge-9 is down")["kind"] == "turn"

    def test_limits_survive_a_restart(self, tmp_path):
        clock = Clock()
        cfg = config(tmp_path, [file_trigger(tmp_path)])
        assert dispatcher(tmp_path, cfg, clock=clock).handle("node-down", "node edge-7 is down")["kind"] == "turn"
        again = dispatcher(tmp_path, cfg, clock=clock)
        assert again.handle("node-down", "node edge-7 is down")["kind"] == "suppressed"

    def test_max_concurrent_turns(self, tmp_path):
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]))
        d._running = 1
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "busy"


class TestKillSwitch:
    def _state(self, **change):
        ks = pytest.importorskip("integrity_killswitch.killswitch")
        ks.configure({})
        path = ks.state_path()
        state = ks.init_state()
        for key, value in change.items():
            if key == "off":
                state["vendors"][value]["enabled"] = False
            else:
                state[key] = value
        ks.save_state(path, state, "test")

    def test_master_panic_runs_nothing(self, tmp_path):
        self._state(master_panic=True)
        calls = []
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]),
                       route_runner=lambda argv, timeout: calls.append(argv) or (0, "", ""))
        record = d.handle("node-down", "node edge-7 is down")
        assert record["kind"] == "blocked" and "PANIC" in record["reason"] and calls == []

    def test_the_adapter_vendor_is_asked(self, tmp_path):
        self._state(off="claude")
        stub = [PY, "-c", "print('agent ran')"]
        cfg = config(tmp_path, [file_trigger(tmp_path, adapter="stub-agent"),
                                file_trigger(tmp_path, trigger_id="node-down-route")],
                     adapters={"stub-agent": {"vendor": "claude", "argv": stub}})
        d = dispatcher(tmp_path, cfg)
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "blocked"
        assert d.handle("node-down-route", "node edge-7 is down")["kind"] == "turn"  # vendor "service" is on

    def test_service_off_stops_the_model_free_route_adapter(self, tmp_path):
        self._state(off="service")
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]))
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "blocked"

    def test_a_missing_kill_switch_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sys.modules, "integrity_killswitch", None)
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]))
        record = d.handle("node-down", "node edge-7 is down")
        assert record["kind"] == "blocked" and "not installed" in record["reason"]
        relaxed = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)], killswitch={"required": False}))
        assert relaxed.handle("node-down", "node edge-8 is down")["kind"] == "turn"


class TestValidation:
    @pytest.mark.parametrize("argv", [
        ["claude", "-p", "{{prompt}}", "--dangerously-skip-permissions"],
        ["claude", "-p", "{{prompt}}", "--permission-mode", "bypassPermissions"],
        ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "{{prompt}}"],
        ["codex", "exec", "--sandbox", "danger-full-access", "{{prompt}}"],
        ["claude", "-p", "{{prompt}}", "--permission-mode=bypassPermissions"],
        ["claude", "-p", "{{prompt}}", "--dangerously-skip-permissions=true"],
        ["claude", "-p", "{{prompt}}", "--allow-dangerously-skip-permissions"],
        ["codex", "exec", "--sandbox=danger-full-access", "{{prompt}}"],
        ["codex", "exec", "-c", 'sandbox_mode="danger-full-access"', "{{prompt}}"],
        ["codex", "exec", "--yolo", "{{prompt}}"],
        ["claude", "-p", "{{prompt}}", "--settings", '{"permissions": {"defaultMode": "BypassPermissions"}}'],
        ["gemini", "--approval-mode=yolo", "-p", "{{prompt}}"],
        ["gemini", "--approval-mode", "YOLO", "-p", "{{prompt}}"],
    ])
    def test_adapters_that_skip_permissions_are_refused(self, tmp_path, argv):
        vendor = "codex" if argv[0] == "codex" else "claude"
        cfg = config(tmp_path, [], adapters={"agent": {"vendor": vendor, "argv": argv}})
        with pytest.raises(rb.RunbookError, match="bypass"):
            rb.validate_config(cfg)

    @pytest.mark.parametrize("vendor", ["service", "unknown_llm"])
    def test_a_command_adapter_cannot_use_a_reserved_vendor(self, tmp_path, vendor):
        # "service" is the model-free route adapter's switch; a command must not borrow it.
        cfg = config(tmp_path, [], adapters={"agent": {"vendor": vendor, "argv": [PY, "-c", "print(1)"]}})
        with pytest.raises(rb.RunbookError, match="reserved"):
            rb.validate_config(cfg)

    @pytest.mark.parametrize(("argv", "vendor"), [
        (["claude", "-p", "{{prompt}}"], "codex"),
        (["C:\\tools\\Claude.EXE", "-p", "{{prompt}}"], "grok"),
        (["/usr/local/bin/codex.cmd", "exec", "{{prompt}}"], "claude"),
        (["npx", "-y", "claude", "-p", "{{prompt}}"], "codex"),
        (["env", "LLM_VENDOR=x", "codex", "exec", "{{prompt}}"], "claude"),
        # A command string handed to a shell names its program too.
        (["cmd", "/c", "claude", "-p", "{{prompt}}"], "grok"),
        (["sh", "-c", "claude -p {{prompt}}"], "grok"),
        (["pwsh", "-Command", "claude -p {{prompt}}"], "grok"),
        (["bash", "-lc", "codex exec x"], "claude"),
        (["sh", "-c", "cd work && '/opt/tools/claude.sh' -p \"{{prompt}}\""], "grok"),
    ])
    def test_the_vendor_must_match_the_program(self, tmp_path, argv, vendor):
        cfg = config(tmp_path, [], adapters={"agent": {"vendor": vendor, "argv": argv}})
        with pytest.raises(rb.RunbookError, match="starts a"):
            rb.validate_config(cfg)

    @pytest.mark.parametrize(("argv", "vendor"), [
        (["claude", "-p", "{{prompt}}"], "claude"),
        (["C:\\tools\\claude.exe", "-p", "{{prompt}}"], "claude"),
        (["npx", "codex", "exec", "{{prompt}}"], "codex"),
        ([PY, "agent_stub.py", "{{prompt}}"], "claude"),  # an unnamed program keeps the declared vendor
        (["cmd", "/c", "claude", "-p", "{{prompt}}"], "claude"),
        (["sh", "-c", "claude -p {{prompt}}"], "claude"),
        (["pwsh", "-Command", "claude -p {{prompt}}"], "claude"),
        (["bash", "-lc", "codex exec x"], "codex"),
        # Only the last path component counts: an install folder name is not a program.
        (["D:\\tools\\claude\\venv\\Scripts\\python.exe", "agent_stub.py"], "grok"),
    ])
    def test_a_matching_vendor_is_accepted(self, tmp_path, argv, vendor):
        cfg = config(tmp_path, [], adapters={"agent": {"vendor": vendor, "argv": argv}})
        assert rb.validate_config(cfg)["adapters"]["agent"]["vendor"] == vendor

    def test_programs_of_two_vendors_are_refused(self, tmp_path):
        argv = ["sh", "-c", "claude -p {{prompt}} | codex exec -"]
        for vendor in ("claude", "codex", "grok"):
            cfg = config(tmp_path, [], adapters={"agent": {"vendor": vendor, "argv": argv}})
            with pytest.raises(rb.RunbookError, match="several vendors"):
                rb.validate_config(cfg)

    def test_the_bash_command_string_names_codex(self):
        assert rb.argv_vendors(["bash", "-lc", "codex exec x"]) == ["codex"]
        assert rb.argv_vendors(["cmd", "/c", "claude", "-p", "{{prompt}}"]) == ["claude"]
        assert rb.argv_vendors([PY, "agent_stub.py", "{{prompt}}"]) == []

    def test_the_vendor_binding_works_without_the_kill_switch_package(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sys.modules, "integrity_killswitch", None)
        cfg = config(tmp_path, [], adapters={"agent": {"vendor": "codex", "argv": ["claude", "-p", "{{prompt}}"]}})
        with pytest.raises(rb.RunbookError, match="starts a claude program"):
            rb.validate_config(cfg)

    @pytest.mark.parametrize("address", ["0.0.0.0:5514", "192.0.2.10:8891", "example.invalid:80"])
    def test_listeners_are_loopback_only(self, tmp_path, address):
        cfg = config(tmp_path, [], listen={"syslog_udp": address})
        with pytest.raises(rb.RunbookError, match="loopback"):
            rb.validate_config(cfg)

    def test_trigger_must_fit_its_route(self, tmp_path):
        routes = rb.load_routes(routes_folder(tmp_path))
        bad_group = file_trigger(tmp_path, params={"name": "{{host}}"})
        with pytest.raises(rb.RunbookError, match="group 'host'"):
            rb.validate_config(config(tmp_path, [bad_group]), routes)
        with pytest.raises(rb.RunbookError, match="not a compiled route"):
            rb.validate_config(config(tmp_path, [file_trigger(tmp_path, route_id="example.missing")]), routes)
        with pytest.raises(rb.RunbookError, match="no value for route parameter name"):
            rb.validate_config(config(tmp_path, [file_trigger(tmp_path, match="node down")]), routes)
        timer = {"trigger_id": "tick", "source": {"kind": "timer", "every_s": 10},
                 "route_id": "example.node-read", "params": {"name": "edge-1"}}
        with pytest.raises(rb.RunbookError, match="once a minute"):
            rb.validate_config(config(tmp_path, [timer]), routes)

    def test_the_shipped_example_validates(self):
        folder = REPO / "examples" / "runbook-triggers"
        raw = json.loads((folder / "runbooks.json").read_text(encoding="utf-8"))
        routes = rb.load_routes(folder / "compiled-routes")
        cfg = rb.validate_config(raw, routes)
        assert cfg["enabled"] is False
        assert {routes[t["route_id"]]["safety"] for t in cfg["triggers"]} == {"read", "write"}


class TestSources:
    def test_file_rotation_and_partial_lines(self, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("", encoding="utf-8")
        state = rb.State(tmp_path / "state.json")
        tail = rb.FileTail("t", log, state)
        log.write_text("first\nsecond-without-newline", encoding="utf-8")
        assert tail.read() == ["first"]
        append(log, "")
        assert tail.read() == ["second-without-newline"]
        log.write_text("after rotation\n", encoding="utf-8")  # smaller file: read from the start
        assert tail.read() == ["after rotation"]

    def test_journald_cursor(self, tmp_path):
        answers = iter([
            (0, "-- cursor: s=one\n", ""),
            (0, json.dumps({"MESSAGE": "node edge-7 is down", "__CURSOR": "s=two"}) + "\n", ""),
        ])
        seen = []

        def runner(argv, timeout):
            seen.append(argv)
            return next(answers)

        state = rb.State(tmp_path / "state.json")
        poll = rb.JournaldPoll("j", "example.service", state, runner)
        assert poll.read() == []
        assert poll.read() == ["node edge-7 is down"]
        assert seen[0][-3:] == ["-n", "0", "--show-cursor"] and seen[1][-2:] == ["--after-cursor", "s=one"]
        assert state.data["journald"]["j"] == "s=two"

    def test_timer_fires_on_its_interval(self, tmp_path):
        clock = Clock()
        timer = {"trigger_id": "tick", "source": {"kind": "timer", "every_s": 600},
                 "route_id": "example.node-read", "params": {"name": "edge-1"}, "suppress_s": 1}
        d = dispatcher(tmp_path, config(tmp_path, [timer]), clock=clock)
        assert [r["kind"] for r in d.poll_once()] == ["turn"]
        clock.now += 60
        assert d.poll_once() == []
        clock.now += 600
        assert [r["kind"] for r in d.poll_once()] == ["turn"]

    def test_webhook_on_loopback(self, tmp_path):
        import queue

        inbox = queue.Queue()
        hook = rb.Webhook(("127.0.0.1", 0), {"node-down"}, "test-token-not-a-secret", inbox)
        hook.start()
        try:
            url = f"http://127.0.0.1:{hook.address[1]}/hook/node-down"

            def post(body: bytes, token: str, ctype="text/plain") -> int:
                request = urllib.request.Request(url, data=body, method="POST", headers={
                    "Content-Type": ctype, "X-Integrity-Token": token})
                try:
                    with urllib.request.urlopen(request, timeout=10) as reply:
                        return reply.status
                except urllib.error.HTTPError as exc:
                    return exc.code

            assert post(b"node edge-7 is down", "wrong") == 403
            assert post(b"node edge-7 is down", "test-token-not-a-secret") == 202
            assert post(json.dumps({"line": "node edge-8 is down"}).encode(), "test-token-not-a-secret",
                        "application/json") == 202
            assert post(b"x" * (rb.MAX_LINE + 1), "test-token-not-a-secret") == 413
        finally:
            hook.stop()
        assert [inbox.get_nowait()[2], inbox.get_nowait()[2]] == ["node edge-7 is down", "node edge-8 is down"]
        trigger = file_trigger(tmp_path, source={"kind": "webhook"})
        d = dispatcher(tmp_path, config(tmp_path, [trigger], listen={"webhook_http": "127.0.0.1:8891"}))
        [record] = d.route_pushed("webhook", "node-down", "node edge-7 is down")
        assert record["kind"] == "turn" and record["ok"]

    def test_syslog_datagram_on_loopback(self):
        import queue

        inbox = queue.Queue()
        listener = rb.SyslogUDP(("127.0.0.1", 0), inbox)
        listener.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"<28>sw1 link: node edge-7 is down", listener.address)
            kind, tid, line = inbox.get(timeout=10)
        finally:
            listener.stop()
        assert kind == "syslog" and tid is None and line.endswith("node edge-7 is down")

    def test_serve_loop(self, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("", encoding="utf-8")
        cfg = config(tmp_path, [file_trigger(tmp_path)], limits={"poll_s": 0.2})
        d = dispatcher(tmp_path, cfg)
        d.poll_once()
        append(log, "node edge-7 is down")
        assert d.serve(max_loops=1) == 0
        assert kinds(d) == ["turn"]
        cfg["enabled"] = False
        assert dispatcher(tmp_path, cfg).serve(max_loops=1) == 3


class TestSinks:
    def test_command_sink_gets_turns(self, tmp_path):
        out = tmp_path / "sink.jsonl"
        sink = [PY, "-c", f"import sys; open({out.as_posix()!r}, 'a').write(sys.stdin.read() + '\\n')"]
        cfg = config(tmp_path, [file_trigger(tmp_path)], event_sinks={"command": sink, "kinds": ["turn"]})
        d = dispatcher(tmp_path, cfg)
        d.handle("node-down", "node edge-7 is down")
        d.handle("node-down", "node EDGE is down")  # rejected: not a sink kind here
        events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line]
        assert [e["kind"] for e in events] == ["turn"]
        assert kinds(d) == ["turn", "sink", "rejected"]

    def test_local_memory_sink_writes_a_closed_turn(self, tmp_path):
        local_memory = pytest.importorskip("integrity_guardian.local_memory")
        home = tmp_path / "memory"
        local_memory.LocalMemory.create(home).close()
        cfg = config(tmp_path, [file_trigger(tmp_path)], event_sinks={"local_memory_home": str(home)})
        d = dispatcher(tmp_path, cfg)
        d.handle("node-down", "node edge-7 is down")
        memory = local_memory.LocalMemory(home)
        try:
            found = memory.recall(task="runbook:node-down")
            coverage = memory.coverage()
        finally:
            memory.close()
        assert len(found["events"]) == 1, d.journal.records()
        assert found["events"][0]["details"]["runbook"]["kind"] == "turn"
        assert coverage["counts"].get("unresolved", 0) == 0


class TestNoise:
    """A noisy source must not grow the journal or the sinks by one record per line."""

    def test_a_thousand_rejected_lines_fold_into_a_few_records(self, tmp_path):
        clock = Clock()
        out = tmp_path / "sink.jsonl"
        sink = [PY, "-c", f"import sys; open({out.as_posix()!r}, 'a').write(sys.stdin.read() + '\\n')"]
        cfg = config(tmp_path, [file_trigger(tmp_path)], event_sinks={"command": sink, "kinds": ["rejected"]})
        d = dispatcher(tmp_path, cfg, clock=clock)
        for _ in range(1000):
            assert d.handle("node-down", "node EDGE is down")["kind"] == "rejected"
            clock.now += 0.01
        assert kinds(d) == ["rejected", "sink"]  # one record, the first of the window, reached the sink
        assert len(out.read_text(encoding="utf-8").splitlines()) == 1
        clock.now += 61  # a new window opens and carries the count of the folded ones
        d.handle("node-down", "node EDGE is down")
        rejected = [r for r in d.journal.records() if r["kind"] == "rejected"]
        assert [r["repeats_before"] for r in rejected] == [0, 999]
        d.handle("node-down", "node EDGE is down")
        d.flush_noise()
        records = d.journal.records()
        assert len(records) <= 5 and records[-1]["flush"] is True and records[-1]["folded_count"] == 1
        assert rb.spend_report(records)["by_kind"]["rejected"] == 1002
        assert d.journal.verify()[0]

    def test_a_blocked_flood_is_folded(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sys.modules, "integrity_killswitch", None)  # fails closed: every line is blocked
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]), clock=Clock())
        for i in range(500):
            assert d.handle("node-down", f"node edge-{i} is down")["kind"] == "blocked"
        assert kinds(d) == ["blocked"]

    def test_suppressed_and_busy_are_folded_too(self, tmp_path):
        d = dispatcher(tmp_path, config(tmp_path, [file_trigger(tmp_path)]), clock=Clock())
        assert d.handle("node-down", "node edge-7 is down")["kind"] == "turn"
        for _ in range(50):
            assert d.handle("node-down", "node edge-7 is down")["kind"] == "suppressed"
        d._running = 1
        for i in range(50):
            assert d.handle("node-down", f"node other-{i} is down")["kind"] == "busy"
        assert kinds(d) == ["turn", "suppressed", "busy"]

    def test_the_journal_head_is_read_once(self, tmp_path, monkeypatch):
        journal = rb.Journal(tmp_path / "journal.jsonl")
        reads = []
        original = journal._read_head
        monkeypatch.setattr(journal, "_read_head", lambda: reads.append(1) or original())
        for i in range(200):
            journal.append({"n": i})
        assert reads == [1] and journal.verify() == (True, "200 records, chain intact")
        reopened = rb.Journal(tmp_path / "journal.jsonl")
        assert reopened.append({"n": 200})["seq"] == 201 and reopened.verify()[0]


class TestInstall:
    def test_doctor_warns_about_a_webhook_without_a_token(self, tmp_path):
        home = tmp_path / "instance"
        assert runbooks_cli.main(["init", "--home", str(home)]) == 0
        path = home / "runbooks.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["listen"] = {"webhook_http": "127.0.0.1:8891", "webhook_token_env": None, "syslog_udp": None}
        path.write_text(json.dumps(data), encoding="utf-8")
        rows = {r["check"]: r for r in runbooks_cli.doctor_report(home)["checks"]}
        assert rows["listen:webhook_token"]["result"] == "WARN"
        assert "without a token" in rows["listen:webhook_token"]["detail"]
        data["listen"]["webhook_token_env"] = "EXAMPLE_TOKEN_VARIABLE"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert "listen:webhook_token" not in {r["check"] for r in runbooks_cli.doctor_report(home)["checks"]}

    def test_init_doctor_uninstall(self, tmp_path, capsys):
        home, units = tmp_path / "instance", tmp_path / "units"
        assert runbooks_cli.main(["init", "--home", str(home), "--systemd-user", "--unit-dir", str(units),
                                  "--windows-task"]) == 0
        unit = units / runbooks_cli.UNIT_NAME
        text = unit.read_text(encoding="utf-8")
        assert runbooks_cli.UNIT_MARK in text and "runbooks serve --home" in text
        assert json.loads((home / "runbooks.json").read_text(encoding="utf-8"))["enabled"] is False
        assert "schtasks /Create" in capsys.readouterr().out
        assert runbooks_cli.main(["init", "--home", str(home)]) == 2  # never over an instance
        before = sorted(p.name for p in home.iterdir())
        assert runbooks_cli.main(["doctor", "--home", str(home)]) == 0
        assert sorted(p.name for p in home.iterdir()) == before  # doctor writes nothing
        assert runbooks_cli.main(["uninstall", "--home", str(home)]) == 0
        assert home.exists() and unit.exists()
        assert runbooks_cli.main(["uninstall", "--home", str(home), "--yes"]) == 0
        assert not home.exists() and not unit.exists()

    def test_doctor_reports_a_broken_journal(self, tmp_path):
        home = tmp_path / "instance"
        assert runbooks_cli.main(["init", "--home", str(home)]) == 0
        (home / "journal.jsonl").write_text('{"seq": 1, "prev": "x", "hash": "y", "record": {}}\n',
                                            encoding="utf-8")
        report = runbooks_cli.doctor_report(home)
        assert not report["ok"] and any(r["check"] == "journal" and r["result"] == "FAIL" for r in report["checks"])

    def test_uninstall_refuses_a_foreign_folder(self, tmp_path):
        other = tmp_path / "other"
        other.mkdir()
        (other / "keep.txt").write_text("x", encoding="utf-8")
        assert runbooks_cli.main(["uninstall", "--home", str(other), "--yes"]) == 2
        assert (other / "keep.txt").exists()

    def test_explain_and_report(self, tmp_path, capsys):
        cfg_file = tmp_path / "runbooks.json"
        cfg_file.write_text(json.dumps(config(tmp_path, [file_trigger(tmp_path)])), encoding="utf-8")
        assert runbooks_cli.main(["explain", "node-down", "--line", "node edge-7 is down",
                                  "--file", str(cfg_file)]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["decision"] == "turn" and out["params"] == {"name": "edge-7"}
        assert runbooks_cli.main(["explain", "node-down", "--line", "node $(id) is down",
                                  "--file", str(cfg_file)]) == 1
        assert json.loads(capsys.readouterr().out)["decision"] == "rejected"
        assert runbooks_cli.main(["validate", str(cfg_file)]) == 0

    def test_the_guards_cli_routes_runbooks(self, tmp_path):
        from integrity_guards import cli

        assert cli.main(["runbooks", "doctor", "--home", str(tmp_path / "none")]) == 1


def test_concurrent_turns_respect_the_pool(tmp_path):
    """Turns submitted from the serve loop run in the pool and are all recorded."""
    cfg = config(tmp_path, [file_trigger(tmp_path)], limits={"max_concurrent": 2})
    d = dispatcher(tmp_path, cfg)
    from concurrent.futures import ThreadPoolExecutor

    d._pool = ThreadPoolExecutor(max_workers=2)
    try:
        for i in range(2):
            assert d.handle("node-down", f"node edge-{i} is down")["queued"] is True
        for future in d.futures:
            future.result(timeout=60)
    finally:
        d._pool.shutdown(wait=True)
    deadline = time.monotonic() + 5
    while kinds(d).count("turn") < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert kinds(d).count("turn") == 2 and d._running == 0
    assert threading.active_count() >= 1
