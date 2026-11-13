"""Read-only telnet CLI for D-Link xStack switches (DES-3028 2.91, DES-3200, DGS-3420 ...).

Only whitelisted ``show`` commands are sent. Paging is answered with ``a`` (All) instead of
``disable clipaging``, because that one is a configuration command. Login: ``UserName:`` then
``Password:``; the admin prompt ends with ``#``. A second ``UserName:`` or ``Fail``/``Incorrect``
after the password is a rejection: no retry.

Output parsing is format-generic: xStack prints ``Key : Value`` pairs, several per line separated
by commas, plus tables. ``parse_kv`` turns that into a dict; table rows are kept as text.
"""
from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

# Commands an operator may ask for; anything else is refused before the socket is opened.
SHOW_WHITELIST = re.compile(
    r"^show (switch|stp( ports( [0-9,\-]+)?| instance( \d{1,2})?)?|ports( [0-9,\-]+)?( description| err_disabled)?|"
    r"vlan( vlanid \d+)?|fdb( port \d+| vlan \S+)?|log|traffic control( [0-9,\-]+)?|loopdetect( ports ([0-9,\-]+|all))?|"
    r"safeguard_engine|error ports( [0-9,\-]+)?|packet ports [0-9,\-]+|utilization ports|lldp remote_ports( [0-9,\-]+)?|"
    r"vlan ports( [0-9,\-]+)?|igmp_snooping|time|serial_port|sntp)$")
# Never, even if a future whitelist edit allows it: these print secrets or change state.
SHOW_DENY = re.compile(r"config|account|snmp|password|radius|ssh|tacacs|save|reboot|reset|download|upload|clear|create|delete|erase|\benable\b|\bdisable\b|cable_diag|session|authen|ssl|users|trusted_host", re.I)
# Extra read-only audit commands (audit-only, no state change, no secrets).
# Deliberately excluded: cable_diag (runs a test), show config*/account/users/session/snmp/radius/tacacs/authen*/ssh/ssl.
_PORTS = r"[0-9,\-]+"
SHOW_WHITELIST_EXT = re.compile(
    r"^show (erps( raps_vlan \d+)?|"
    r"link_aggregation( algorithm)?|lacp_port( " + _PORTS + r")?|"
    r"igmp_snooping( group| forwarding| host)?|router_ports|"
    r"dhcp_relay|arpentry|iproute|ipif( [A-Za-z0-9_-]+)?|"
    r"utilization (cpu|ports|dram|flash)|"
    r"bandwidth_control( " + _PORTS + r")?|mirror|port_security( ports " + _PORTS + r")?|dos_prevention|"
    r"multicast_range|filter dhcp_server|ddm( ports " + _PORTS + r"( status)?)?|"
    r"gvrp|qinq( ports " + _PORTS + r")?|vlan_trunk)$")

# The whole pager line must be in the buffer before we answer, or its tail would leak into the output.
ANSI_B = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
PAGER_ALL = re.compile(rb"CTRL\+C[^\n]{0,80}?Quit[^\n]{0,160}?\ba\s+All\b[ \t]*", re.I)
PAGER_PAGE = re.compile(rb"CTRL\+C[^\n]{0,80}?Next Page[^\n]{0,40}?Previous Page[^\n]{0,40}?Refresh\b[ \t]*", re.I)
PAGER_ANY = re.compile(rb"CTRL\+C[^\n]{0,80}?Quit", re.I)
MORE = PAGER_ALL  # backwards name
PROMPT_ADMIN = rb"\n[^\n]*#\s*$"
LOGIN_USER = rb"(user\s*name|login)\s*:\s*$"
LOGIN_PASS = rb"pass\s*word\s*:\s*$"
REJECT = rb"(fail|incorrect|invalid|denied)|(user\s*name|login)\s*:\s*$"
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Sets the owner-facing commands map to.
VIEWS = {
    "switch": ["show switch"],
    "stp": ["show stp"],
    "stp-ports": ["show stp ports"],
    "fbpdu": ["show stp", "show stp ports"],
    "ports": ["show ports"],
    "vlan": ["show vlan"],
    "lbd": ["show loopdetect", "show loopdetect ports all"],
    "storm": ["show traffic control"],
    "fdb": ["show fdb"],
    "log": ["show log"],
    "loop": ["show loopdetect"],
    "stp-full": ["show switch", "show stp", "show stp ports"],
    "all": ["show switch", "show stp", "show stp ports", "show ports", "show vlan", "show loopdetect",
            "show loopdetect ports all", "show traffic control", "show fdb", "show log"],
}


class CliError(Exception):
    """Transport problem: timeout, closed. Outcome unknown, not a rejection."""


class CliRejected(Exception):
    """The switch answered and refused the login."""


# Пакет K: три точных чтения, которые SHOW_DENY иначе режет по слову "config". Только эти формы, целиком:
# имя/ревизия/привязка VLAN региона MSTP, журнал по частям, строки защиты колец из текущего конфига.
# Конфиг читается только с include одного из трёх слов, а вывод ещё раз фильтруется: остаются лишь строки
# config/create/enable/disable/delete stp|erps|loopdetect (если прошивка проигнорирует include, лишнее не уйдёт).
READ_EXACT = re.compile(r'^show (stp mst_config_id|log index \d{1,4}(-\d{1,4})?|config current_config include "(stp|erps|loopdetect)")$')
RING_CONFIG_LINE = re.compile(r"^\s*(config|create|enable|disable|delete)\s+(stp|erps|loopdetect)\b[^\n]*$", re.I)
_RING_SECRETS = re.compile(r"password|community|snmp|radius|tacacs|account|key", re.I)


def allowed(cmd: str) -> bool:
    cmd = " ".join(cmd.split())
    if READ_EXACT.match(cmd):
        return True
    return bool(SHOW_WHITELIST.match(cmd) or SHOW_WHITELIST_EXT.match(cmd)) and not SHOW_DENY.search(cmd)


def ring_config_only(text: str) -> str:
    """Из вывода show config current_config include "...": только строки защиты колец (и строка Command:)."""
    keep = [ln.rstrip() for ln in text.split("\n")
            if (RING_CONFIG_LINE.match(ln) and not _RING_SECRETS.search(ln)) or ln.startswith("Command:")]
    body = [ln for ln in keep if not ln.startswith("Command:")]
    return "\n".join(keep) + ("" if body else "\n(строк stp/erps/loopdetect в выводе нет)")


# Login profiles, opt-in per target. The profile is fixed BEFORE the TCP connect (option replies go out with
# the first bytes of the banner), from --profile or profiles.json "targets".
# * "default" reproduces macro_executor.Telnet / sweep.login byte for byte: every telnet option refused
#   (DO/DONT -> WONT, WILL/WONT -> DONT), lines end with CR LF, no settle wait, no early-reject check.
#   It is what works on DES-1210 / DGS-3420 / DGS-1510 today; stand-tested equal in test_des3028.
# * "dlink-des-legacy" (DES-3028 2.91, DES-3200 1.x): CR-only line end, accept server ECHO + SGA like PuTTY,
#   0.6 s settle before typing, and do not type the password if the switch already said Fail / UserName:.
#   Live: login accepted on a DES-3028 2.91 with this profile.
PROFILES = {
    "default": {"newline": "crlf", "negotiate": "refuse-all", "settle_s": 0.0, "early_reject_guard": False},
    "dlink-des-legacy": {"newline": "cr", "negotiate": "accept-echo-sga", "settle_s": 0.6,
                         "early_reject_guard": True},
}
NEWLINES = {"crlf": "\r\n", "cr": "\r", "crnul": "\r\0"}
LEGACY_BANNER = re.compile(r"(DES-3028|DES-3026|DES-3010|DES-3200|DES-3526|DES-3550|DES-3828)", re.I)
ECHO, SGA = 1, 3
NEGOTIATION = {"refuse-all": (set(), set()), "accept-echo-sga": ({ECHO, SGA}, {SGA})}   # (accept WILL, accept DO)
PROFILE_MAP = Path(__file__).resolve().parent / "profiles.json"


def profile_for_target(ip: str) -> str:
    try:
        return json.loads(PROFILE_MAP.read_text(encoding="utf-8")).get("targets", {}).get(ip, "default")
    except (OSError, ValueError):
        return "default"


def _mask(text: bytes, secret: bytes) -> bytes:
    """Remove the secret and any 3+ byte piece of it (an echo split across packets) from recorded text."""
    for k in range(len(secret), 2, -1):
        for i in range(len(secret) - k + 1):
            piece = secret[i:i + k]
            if piece in text:
                text = text.replace(piece, b"<redacted>")
    return text


class Telnet:
    def __init__(self, host: str, port: int = 23, timeout: float = 15.0, negotiate: str = "refuse-all",
                 newline: str = "crlf"):
        self.accept_will, self.accept_do = NEGOTIATION[negotiate]
        self.newline = NEWLINES[newline]
        try:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise CliError(f"connect {host}:{port}: {type(exc).__name__}") from None
        self.buf = b""
        self.timeout = timeout
        self.transcript: list[tuple[str, str]] = []     # (dir, text); password sends are redacted
        self.record = True
        self._secret: bytes | None = None
        self.negotiated: list[str] = []
        self.page_idle = 3.0

    def _reply(self, cmd: int, opt: int) -> None:
        if cmd == WILL:
            ans = DO if opt in self.accept_will else DONT
        elif cmd == DO:
            ans = WILL if opt in self.accept_do else WONT
        elif cmd == WONT:
            ans = DONT
        else:  # DONT
            ans = WONT
        self.sock.sendall(bytes([IAC, ans, opt]))
        names = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}
        self.negotiated.append(f"srv {names[cmd]} {opt} -> cli {names[ans]} {opt}")

    def _recv(self) -> bytes:
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            raise CliError("read timeout") from None
        except OSError as exc:
            raise CliError(type(exc).__name__) from None
        if not data:
            raise CliError("telnet closed by peer")
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                    self._reply(cmd, data[i + 2])
                    i += 3
                    continue
                if cmd == SB:
                    j = data.find(bytes([IAC, SE]), i)
                    i = len(data) if j < 0 else j + 2
                    continue
                if cmd == IAC:
                    out.append(IAC)
                i += 2
                continue
            out.append(b)
            i += 1
        if self.record:
            text = bytes(out)
            if self._secret:
                text = _mask(text, self._secret)
            self.transcript.append(("recv", text.decode("latin-1")))
        return bytes(out)

    def drain(self, seconds: float) -> None:
        """Wait ``seconds`` and pull in whatever the switch still prints (part of the prompt, echo)."""
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            self.sock.settimeout(left)
            try:
                self.buf += self._recv()
            except CliError as exc:
                if "timeout" in str(exc):
                    return
                raise

    def read_until(self, pattern: bytes, timeout: float | None = None, pager: bool = False) -> str:
        """Read until ``pattern``. With ``pager``: answer D-Link pagers (DES-3028 2.91, seen live):
        * "... ENTER Next Entry a All"           -> 'a' (dump the rest);
        * "... n Next Page p Previous Page r Refresh" (interactive pages, e.g. show stp ports / show ports)
          -> 'n' for the next page; when a page repeats or nothing new comes for ``page_idle`` s -> 'q'.
        ANSI attribute codes inside the pager line are stripped before matching."""
        rx = re.compile(pattern, re.S | re.I)
        end = time.monotonic() + (timeout or self.timeout)
        collected = b""
        quit_sent = False
        n_sent_at = None
        while True:
            self.buf = ANSI_B.sub(b"", self.buf)
            m = rx.search(self.buf)
            if m and not (pager and PAGER_ANY.search(self.buf[:m.end()])):
                collected += self.buf[:m.end()]
                self.buf = self.buf[m.end():]
                return collected.decode("utf-8", "replace")
            if pager:
                ma = PAGER_ALL.search(self.buf)
                mp = PAGER_PAGE.search(self.buf)
                if ma and (not mp or ma.start() <= mp.start()):
                    collected += self.buf[:ma.start()]
                    self.buf = self.buf[ma.end():]
                    self.sock.sendall(b"a")
                    continue
                if mp:
                    # Interactive page mode. 'n' paging proved unreliable on 2.91 (live: page 2 repeated),
                    # so callers size commands to one page (per port / 8-port ranges) and we quit with 'q'.
                    collected += self.buf[:mp.start()]
                    self.buf = self.buf[mp.end():]
                    if not quit_sent:
                        self.sock.sendall(b"q")
                        quit_sent = True
                    continue
            left = end - time.monotonic()
            if left <= 0:
                raise CliError("prompt not seen before timeout")
            wait = left
            if n_sent_at is not None and not quit_sent:
                wait = min(left, max(0.2, self.page_idle - (time.monotonic() - n_sent_at)))
            self.sock.settimeout(max(0.2, wait))
            try:
                self.buf += self._recv()
            except CliError as exc:
                if "timeout" in str(exc) and n_sent_at is not None and not quit_sent \
                        and time.monotonic() - n_sent_at >= self.page_idle:
                    self.sock.sendall(b"q")       # last page: 'n' produced nothing new
                    quit_sent = True
                    n_sent_at = None
                    continue
                if "timeout" in str(exc) and time.monotonic() < end:
                    continue
                raise

    def send(self, text: str, secret: bool = False) -> None:
        data = text.encode("latin-1")
        if secret:
            self._secret = data
        self.sock.sendall(data + self.newline.encode("latin-1"))
        if self.record:
            shown = "<password redacted>" if secret else text
            self.transcript.append(("send", shown + self.newline.encode("unicode_escape").decode()))

    def close(self) -> None:
        self._secret = None
        try:
            self.sock.close()
        except OSError:
            pass


class CliSession:
    def __init__(self, host: str, port: int = 23, login_timeout: float = 30.0, cmd_timeout: float = 90.0,
                 profile: str | None = None):
        self.host, self.port = host, port
        self.login_timeout, self.cmd_timeout = login_timeout, cmd_timeout
        self.t: Telnet | None = None
        self.banner = ""
        self.prompt = ""
        self.profile = profile
        self.log: list[dict] = []

    def login_transcript(self) -> dict:
        t = self.t
        return {"profile": self.profile, "negotiation": t.negotiated if t else [],
                "exchange": t.transcript if t else []}

    def login(self, user: str, password: str) -> str:
        """One attempt. Returns the banner. Raises CliRejected on an explicit refusal."""
        self.profile = self.profile or profile_for_target(self.host)
        prof = PROFILES[self.profile]
        self.t = Telnet(self.host, self.port, timeout=self.login_timeout, negotiate=prof["negotiate"],
                        newline=prof["newline"])
        first = self.t.read_until(LOGIN_USER + b"|" + LOGIN_PASS, self.login_timeout)
        self.banner = ANSI.sub("", first)
        if self.profile == "default" and LEGACY_BANNER.search(self.banner):
            self.t.transcript.append(("note", "banner looks like old xStack; profile dlink-des-legacy may be needed"))
        if prof["settle_s"]:
            self.t.drain(prof["settle_s"])
        if re.search(LOGIN_USER, first.encode("latin-1", "replace"), re.I):
            self.t.send(user)
            if not prof["early_reject_guard"]:
                self.t.read_until(LOGIN_PASS, self.login_timeout)
            else:
                got = self.t.read_until(LOGIN_PASS + b"|" + REJECT, self.login_timeout)
                if re.search(rb"(fail|incorrect|denied)|(user\s*name|login)\s*:\s*$",
                             got.encode("latin-1", "replace"), re.I):
                    raise CliRejected("switch rejected before the password was typed (stray line ending?)")
                try:
                    self.t.drain(prof["settle_s"])
                except CliError:
                    pass
                # Fail / UserName: already in the buffer means the switch took something else (a stray LF) as
                # the password. Do not type the password now: it would be read as the next user name.
                if re.search(rb"(fail|incorrect|denied)|(user\s*name|login)\s*:\s*$", self.t.buf, re.I):
                    raise CliRejected("switch rejected before the password was typed (stray line ending?)")
        self.t.send(password, secret=True)
        password = None  # noqa: F841
        out = self.t.read_until(PROMPT_ADMIN + b"|" + rb"\n[^\n]*>\s*$|" + REJECT, self.login_timeout)
        tail = out.rstrip()
        if tail.endswith("#"):
            self.prompt = tail.splitlines()[-1].strip()
            return self.banner
        try:
            self.t.drain(2.0)               # keep what the switch says after a refusal, for the access-gap record
        except CliError:
            pass
        if tail.endswith(">"):
            raise CliError("login landed in user mode '>' (not admin); read commands may still work but "
                           "this tool expects '#'")
        raise CliRejected("switch refused the login")

    def port_count(self) -> int:
        if getattr(self, "_ports", None):
            return self._ports
        m = re.search(r"Device Type\s*:\s*D[EG]S-(\d{4})(?:-(\d+))?", self._raw("show switch"))
        n = 28
        if m:
            n = int(m.group(2)) if m.group(2) else int(m.group(1)[-2:])
        self._ports = n if 4 <= n <= 52 else 28
        return self._ports

    def run(self, cmd: str) -> str:
        cmd = " ".join(cmd.split())
        if not allowed(cmd):
            raise ValueError(f"command not allowed (read-only whitelist): {cmd!r}")
        legacy = self.profile == "dlink-des-legacy"
        if legacy and cmd == "show stp ports":
            return "\n\n".join(self._raw(f"show stp ports {p}") for p in range(1, self.port_count() + 1))
        if legacy and cmd == "show ports":
            n = self.port_count()
            return "\n".join(self._raw(f"show ports {a}-{min(a + 7, n)}") for a in range(1, n + 1, 8))
        return self._raw(cmd)

    def _raw(self, cmd: str) -> str:
        assert allowed(cmd), cmd
        assert self.t is not None
        t0 = time.monotonic()
        self.t.send(cmd)
        out = self.t.read_until(PROMPT_ADMIN, self.cmd_timeout, pager=True)
        self.log.append({"cmd": cmd, "bytes": len(out), "seconds": round(time.monotonic() - t0, 1)})
        if cmd.startswith("show config "):
            return ring_config_only(clean(out, cmd))
        return clean(out, cmd)

    def logout(self) -> None:
        if self.t:
            try:
                self.t.send("logout")
                time.sleep(0.3)
            except OSError:
                pass
            self.t.close()
            self.t = None


def clean(out: str, cmd: str) -> str:
    text = ANSI.sub("", out).replace("\r", "").replace("\x00", "")
    lines = [ln.rstrip() for ln in text.split("\n")]
    if lines and lines[0].strip() == cmd:
        lines = lines[1:]
    if lines and re.match(r".*#\s*$", lines[-1]):
        lines = lines[:-1]
    out_lines: list[str] = []
    for ln in lines:
        if not ln and out_lines and not out_lines[-1]:
            continue
        out_lines.append(ln)
    return "\n".join(out_lines).strip("\n")


# --------------------------------------------------------------------------- parsing
_KV = re.compile(r"\s*([A-Za-z][A-Za-z0-9 ./()\-]*?)\s*:\s*(.*?)\s*$")


def parse_kv(text: str) -> dict:
    """``Key : Value`` pairs, including several per line separated by ' , '."""
    out: dict = {}
    for line in text.splitlines():
        if ":" not in line or line.strip().startswith("Command:"):
            continue
        for part in re.split(r"\s,\s*|,\s{2,}", line):
            m = _KV.match(part)
            if m and m.group(1) and len(m.group(1)) < 40:
                key = re.sub(r"\s+", " ", m.group(1)).strip()
                out.setdefault(key, m.group(2).rstrip(" ,"))
    return out


def parse_stp_ports(text: str) -> list[dict]:
    """Split ``show stp ports`` into one block per ``Port Index``; each block is parsed as kv + table rows."""
    blocks = re.split(r"(?=^\s*Port Index\s*:)", text, flags=re.M)
    ports = []
    for b in blocks:
        m = re.match(r"\s*Port Index\s*:\s*(\d+)", b)
        if not m:
            continue
        kv = parse_kv(b)
        rows = [r.split() for r in b.splitlines() if re.match(r"\s*\d+\s+\S+\s+\d+\s+\d+\s+\w+\s+\w+", r)]
        item = {"port": int(m.group(1)), "fields": kv}
        if rows:
            item["msti"] = [{"msti": r[0], "designated_bridge": r[1], "path_cost": r[2], "priority": r[3],
                             "status": r[4], "role": r[5]} for r in rows]
        fb = next((v for k, v in kv.items() if "forward bpdu" in k.lower() or k.lower() == "fbpdu"), None)
        if fb is not None:
            item["fbpdu"] = fb
        ps = next((v for k, v in kv.items() if k.lower() in ("port stp", "stp")), None)
        if ps is None:
            mm = re.search(r"Port STP\s*:?\s*(Enabled|Disabled)", b)
            ps = mm.group(1) if mm else None
        if ps is not None:
            item["port_stp"] = ps
        ml = re.search(r"\bLBD\s*:\s*(\w+)", b)
        if ml:
            item["lbd"] = ml.group(1)
        ports.append(item)
    return ports


def parse_ports(text: str) -> list[dict]:
    """show ports (2.91): 'N  Enabled  Auto/Disabled  100M/Full/None  Enabled' (+ MDI line). Fiber/combo ports
    may carry (C)/(F) after the number."""
    out = []
    for m in re.finditer(r"^\s*(\d+)\s*(\((?:C|F)\))?\s+(Enabled|Disabled)\s+(\S+)\s+(\S+)\s+(Enabled|Disabled)\s*$",
                         text, re.M):
        conn = m.group(5)
        out.append({"port": int(m.group(1)), "medium": {"(C)": "copper", "(F)": "fiber"}.get(m.group(2) or ""),
                    "state": m.group(3), "settings": m.group(4), "connection": conn,
                    "link_up": not conn.lower().startswith("linkdown"), "learning": m.group(6)})
    return out


def parse_fdb(text: str) -> list[dict]:
    return [{"vid": int(m.group(1)), "vlan": m.group(2), "mac": m.group(3), "port": m.group(4), "type": m.group(5)}
            for m in re.finditer(r"^\s*(\d+)\s+(\S+)\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+(\S+)\s+(\S+)",
                                 text, re.M)]


def parse_vlans(text: str) -> list[dict]:
    out = []
    for block in re.split(r"(?=^VID\s*:)", text, flags=re.M):
        if not block.startswith("VID"):
            continue
        kv = {}
        for line in block.splitlines():
            for m in re.finditer(r"([A-Za-z][A-Za-z ]*?)\s*:\s*(\S*(?:\s\S+)*?)(?=\s{2,}[A-Za-z][A-Za-z ]*?\s*:|\s*$)", line):
                kv[re.sub(r"\s+", " ", m.group(1)).strip()] = m.group(2).strip()
        out.append({"vid": int(kv.get("VID", "0") or 0), "name": kv.get("VLAN Name"),
                    "tagged": kv.get("Current Tagged Ports", ""), "untagged": kv.get("Current Untagged Ports", ""),
                    "static_tagged": kv.get("Static Tagged Ports", ""),
                    "static_untagged": kv.get("Static Untagged Ports", ""), "members": kv.get("Member Ports", "")})
    return out


def parse_traffic(text: str) -> list[dict]:
    return [{"port": int(m.group(1)), "threshold": int(m.group(2)), "broadcast": m.group(3), "multicast": m.group(4),
             "unicast": m.group(5), "action": m.group(6)}
            for m in re.finditer(r"^\s*(\d+)\s+(\d+)\s+(Enabled|Disabled)\s+(Enabled|Disabled)\s+(Enabled|Disabled)\s+(\w+)",
                                 text, re.M)]


def ports_list(spec: str) -> list[int]:
    out: list[int] = []
    for part in re.findall(r"\d+(?:-\d+)?", spec or ""):
        a, _, b = part.partition("-")
        out.extend(range(int(a), int(b or a) + 1))
    return out


def summarise(outputs: dict) -> dict:
    """Normalised view of whatever show outputs were collected."""
    res = _summarise_core(outputs)
    if "show ports" in outputs:
        res["ports"] = parse_ports(outputs["show ports"])
    if "show fdb" in outputs:
        fdb = parse_fdb(outputs["show fdb"])
        per_port: dict = {}
        for e in fdb:
            per_port[e["port"]] = per_port.get(e["port"], 0) + 1
        res["fdb"] = {"entries": len(fdb), "per_port": per_port, "rows": fdb}
    if "show vlan" in outputs:
        res["vlans"] = parse_vlans(outputs["show vlan"])
    if "show traffic control" in outputs:
        tc = parse_traffic(outputs["show traffic control"])
        res["storm"] = {"ports": tc, "broadcast_enabled_ports": [x["port"] for x in tc if x["broadcast"] == "Enabled"]}
    if "show loopdetect" in outputs:
        res["loopdetect"] = parse_kv(outputs["show loopdetect"])
    # uplink/ring candidates: ports that carry tagged VLANs or the most learned MACs
    tagged = sorted({p for v in res.get("vlans", []) for p in ports_list(v.get("tagged", ""))})
    up = [x["port"] for x in res.get("ports", []) if x["link_up"]]
    fdb_pp = (res.get("fdb") or {}).get("per_port", {})
    busiest = sorted(((n, p) for p, n in fdb_pp.items() if p.isdigit()), reverse=True)[:2]
    res["uplink_candidates"] = {"tagged_ports": tagged, "links_up": up,
                                "most_macs": [{"port": int(p), "macs": n} for n, p in busiest]}
    return res


def render_summary(res: dict) -> str:
    """Short human summary printed above the raw switch text."""
    d, st = res.get("device") or {}, res.get("stp") or {}
    lines = []
    if d:
        lines.append(f"Device   : {d.get('type')}  FW {d.get('firmware')}  HW {d.get('hardware')}  MAC {d.get('mac')}")
    if st:
        lines.append(f"STP      : {st.get('status')} ({st.get('version')})  Forwarding BPDU: {st.get('forwarding_bpdu')}")
    sp = res.get("stp_ports")
    if sp:
        fb_off = [x["port"] for x in sp if str(x.get("fbpdu", "")).lower().startswith("disabled")]
        edge = [x["port"] for x in sp if str(x.get("fields", {}).get("Edge Port", "")).lower().startswith("true")]
        lines.append(f"STP ports: {len(sp)} read; fBPDU off on {fb_off or 'none'}; edge {edge or 'none'}")
    if res.get("ports"):
        up = [f"{x['port']}:{x['connection']}" for x in res["ports"] if x["link_up"]]
        lines.append(f"Links up : {', '.join(up) or 'none'}")
    if res.get("storm"):
        lines.append(f"Storm    : broadcast enabled on {res['storm']['broadcast_enabled_ports'] or 'no ports'}")
    ld = res.get("loopdetect") or {}
    if ld:
        g = lambda *ks: next((ld[k] for k in ks if k in ld), None)  # noqa: E731  DES-3028 vs DES-3200 key names
        lines.append(f"LBD      : {g('Loopdetect Status', 'LBD Status')}  mode {g('LBD Mode', 'Loopdetect Mode') or '-'}"
                     f"  interval {g('Loopdetect Interval', 'LBD Interval')}  recover {g('Recover Time', 'LBD Recover Time')}")
    if res.get("vlans"):
        lines.append("VLANs    : " + "; ".join(f"{v['vid']} {v['name']} T[{v['tagged']}] U[{v['untagged']}]"
                                             for v in res["vlans"]))
    if res.get("fdb"):
        lines.append(f"FDB      : {res['fdb']['entries']} entries; per port {res['fdb']['per_port']}")
    uc = res.get("uplink_candidates") or {}
    if uc.get("tagged_ports") or uc.get("most_macs"):
        lines.append(f"Uplinks? : tagged {uc.get('tagged_ports')}  most MACs {uc.get('most_macs')}")
        cand = sorted(set(uc.get("tagged_ports") or []) | {m["port"] for m in uc.get("most_macs") or []})
        roles = []
        for x in res.get("stp_ports") or []:
            if x["port"] in cand:
                m0 = (x.get("msti") or [{}])[0]
                roles.append(f"{x['port']}:{m0.get('status')}/{m0.get('role')} fBPDU {x.get('fbpdu')}")
        if roles:
            lines.append(f"Uplink STP: {', '.join(roles)}")
    return "\n".join(lines)


def _summarise_core(outputs: dict) -> dict:
    sw = parse_kv(outputs.get("show switch", ""))
    stp = parse_kv(outputs.get("show stp", ""))
    res = {"device": {"type": sw.get("Device Type"), "firmware": sw.get("Firmware Version"),
                      "hardware": sw.get("Hardware Version"), "mac": sw.get("MAC Address"),
                      "ip": sw.get("IP Address"), "uptime": sw.get("System Uptime"),
                      "spanning_tree": sw.get("Spanning Tree"), "telnet": sw.get("Telnet"), "web": sw.get("Web"),
                      "cli_paging": sw.get("CLI Paging")} if sw else None,
           "stp": {"status": stp.get("STP Status"), "version": stp.get("STP Version"),
                   "max_age": stp.get("Max Age"), "forward_delay": stp.get("Forward Delay"),
                   "forwarding_bpdu": stp.get("Forwarding BPDU"), "fields": stp} if stp else None}
    if "show stp ports" in outputs:
        res["stp_ports"] = parse_stp_ports(outputs["show stp ports"])
    return res
