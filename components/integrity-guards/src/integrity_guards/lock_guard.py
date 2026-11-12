"""PreToolUse guard: host-changing actions require a live Integrity lock, and nobody else's.

Harness-neutral. `check` reads one hook JSON object on stdin ({"tool_name", "tool_input",
"session_id"}) and prints a hook decision; `record` (PostToolUse) caches the Integrity view.

Lock state is the Integrity view, never a private registry:
  * others' locks: the last admission coordination snapshot (active_locks), cached per session;
  * own locks: receipts of this session's integrity_append_event kind=lock, cached per session,
    because a turn's admission snapshot is frozen.
Only the command that runs ON the remote host is classified; local redirects, local file
operations and option values (ssh -F config paths) never count. Mode "shadow" only warns.
v2: review fixes (review round 1, P1/P2/P3).
v4: review round 3: compound remote commands, pipe/heredoc into an interpreter,
ssh options after the host and RemoteCommand, one PREFIXES table, Proxmox pct/qm (guest by vmid), php/node/ruby,
PowerShell remoting and UNC writes, more verbs and fewer false denies (iptables -nvL, nft list).
v3: review round 2: Windows ssh.exe/full paths/PowerShell `&`; code that wrappers run
(sh -c, eval, python -c, perl -e, awk, find -exec/-delete, xargs, su -c, cmd /c, powershell -Command,
$(...)) is classified recursively; sftp sessions; glued curl flags. Known limit: a command name built at
run time ($(echo ssh), variables, aliases) is not resolved.

Configuration (no value here names a particular network):
  INTEGRITY_LOCK_GUARD_HOSTS  or lock_guard.hosts_file   host table (see examples/hosts.example.json)
  INTEGRITY_LOCK_GUARD_STATE  or lock_guard.state_dir    per-session lock cache
  INTEGRITY_LOCK_GUARD_SERVER_LOCKS=1 or lock_guard.server_lock_kind  the memory server accepts kind=lock
  INTEGRITY_LOCK_GUARD_SSH_CONFIGS or lock_guard.standard_ssh_configs  extra regexes for trusted ssh -F files
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import shlex
import sys
from pathlib import Path

from integrity_guards import config as _config

_CFG = _config.section("lock_guard")
STATE_DIR = Path(os.environ.get("INTEGRITY_LOCK_GUARD_STATE") or _CFG.get("state_dir")
                 or _config.state_root() / "lock-guard")
_HOSTS_SOURCE = os.environ.get("INTEGRITY_LOCK_GUARD_HOSTS") or _CFG.get("hosts_file")
DEFAULT_HOSTS = Path(_HOSTS_SOURCE) if _HOSTS_SOURCE else None
SHELL_TOOLS = {"Bash", "PowerShell", "shell", "exec_command", "local_shell"}
# v11: set when the memory server's append schema accepts kind=lock; until then no agent can take
# an own lock, so shadow mode stays silent unless a foreign lock is cached.
SERVER_LOCK_KIND = (os.environ.get("INTEGRITY_LOCK_GUARD_SERVER_LOCKS") == "1"
                    or _CFG.get("server_lock_kind") is True)
UTC = dt.timezone.utc

SSH_ARG_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")           # ssh/plink options that take a value
PLINK_ARG_OPTS = {"-P", "-l", "-pw", "-pwfile", "-i", "-hostkey", "-m", "-proxycmd", "-L", "-R", "-D",
                  "-sercfg", "-sshlog", "-sshrawlog", "-loghost", "-pwfile"}
SFTP_ARG_OPTS = set("BbcDFiJloPRSsX")
COPY_TOOLS = {"scp", "rsync", "pscp"}                   # names are compared without .exe
SSH_TOOLS = {"ssh", "plink", "autossh", "putty", "kitty"}   # v5: putty/kitty sessions
REMOTE_TOOLS = r"(?:autossh|ssh|plink|putty|kitty|scp|sftp|rsync|pscp)"
SEPARATORS = {";", "&&", "||", "|", "&", "\n", ";;", ";&", ";;&", "|&"}
LOCALHOSTS = {"localhost", "127.0.0.1", "::1"}

FIRST_WORD = {"reboot", "shutdown", "poweroff", "halt", "rm", "rmdir", "mv", "cp", "dd", "chmod", "chown",
              "chgrp", "ln", "mkdir", "touch", "truncate", "rsync", "kill", "pkill", "killall", "useradd",
              "usermod", "userdel", "groupadd", "passwd", "mount", "umount", "install", "patch", "unzip",
              "crontab", "visudo", "netplan", "modprobe", "sysctl", "swapon", "swapoff", "fallocate",
              "unlink", "shred", "chattr", "setfacl", "wipefs",       # v4
              "scp", "pscp", "sftp"}   # v4: a copy that survives _drop_calls writes onto this host (download)
# v4: ONE prefix table for local and remote commands: name -> options that take a value. Runners (xargs,
# watch) run their arguments: they count for the command position but _embedded classifies what they run.
PREFIXES = {"sudo": {"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R"}, "doas": {"-u", "-C"},
            "nohup": set(), "time": {"-f", "-o"}, "exec": {"-a"}, "command": set(), "builtin": set(),
            "env": {"-u", "-C", "-S"}, "timeout": {"-s", "-k"}, "nice": {"-n"}, "ionice": {"-c", "-n", "-p", "-P", "-u"},
            "stdbuf": {"-i", "-o", "-e"}, "setsid": set(), "sshpass": {"-p", "-f", "-d", "-P"}, "busybox": set(),
            "wsl": {"-d", "--distribution", "-u", "--user", "--cd"}, "xargs": {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"},
            "watch": {"-n", "--interval"}, "if": set(), "then": set(), "elif": set(), "else": set(), "do": set(),
            "while": set(), "until": set(), "!": set(), "{": set(), "(": set()}
RUNNERS = {"xargs", "watch"}
COMPOUND_END = {"done", "fi", "esac", "}", ")", ";;"}
PATTERNS = [
    r"^systemctl\s+(?:--\S+\s+)*(?:start|stop|restart|reload|try-restart|reload-or-restart|enable|disable|mask|unmask|kill|daemon-reload|set-property|edit)\b",
    r"^service\s+\S+\s+(?:start|stop|restart|reload)\b",
    r"^virsh\s+(?:-\S+\s+(?:\S+\s+)?)*(?:start|shutdown|destroy|reboot|reset|setmem|setmaxmem|setvcpus|edit|define|undefine|attach-\w+|detach-\w+|snapshot-create\S*|snapshot-delete|snapshot-revert|blockcommit|blockpull|migrate|autostart)\b",
    r"^(?:apt|apt-get)\s+(?:-\S+\s+)*(?:install|remove|purge|upgrade|dist-upgrade|autoremove|update)\b",
    r"^dpkg\s+-(?:i|r|P|-install|-remove|-purge)\b", r"^pip3?\s+(?:install|uninstall)\b",
    r"^python\S*\s+-m\s+pip\s+(?:install|uninstall)\b", r"^npm\s+(?:install|ci|i|update|uninstall|remove|rm|rebuild)\b",
    r"^git\s+(?:(?:-C|-c|--git-dir|--work-tree)\s+\S+\s+|--?\S+\s+)*(?:pull|checkout|switch|reset|clean|merge|rebase|commit"
    r"|push|stash|apply|am|cherry-pick|revert|restore|rm|mv|init|clone|gc|prune|branch\s+-[dDmM]|tag\s+(?!-l\b|--list\b)\S)\b",
    r"(?-i:^sed\b.*\s(?:-[A-Za-z]*i\S*|--in-place\S*)(?=\s|$))",                       # v4: --in-place, -ni
    r"(?-i:^tar\s+(?:-?[A-Za-wyz]*x|.*\s(?:-[A-Za-z]*x[A-Za-z]*|--extract|--get|--delete)\b))",   # v3: tar -C d -xf
    r"^tee\s+(?!-a\s+/dev/null|/dev/null)\S",
    r"^docker(?:-compose)?\s+(?:-\S+\s+(?:\S+\s+)?)*(?:run|rm|rmi|stop|start|restart|kill|exec|create|update|pull|load"
    r"|import|commit|tag|cp|pause|unpause|rename|prune|build|up|down|(?:container|image|network|volume|system|builder)\s+"
    r"(?:rm|prune|create|stop|start|restart|kill|connect|disconnect|remove)|compose\s+(?:-\S+\s+(?:\S+\s+)?)*"
    r"(?:up|down|restart|rm|stop|start|pull|build|create|kill|run|exec|pause|unpause))\b",          # v4: compose -f x up
    r"^vtysh\b.*(?:conf(?:igure)?\s+t|\bclear\b|\bwrite\b|\bcopy\b)",
    r"^ip\s+(?:-\S+\s+)*(?:addr|address|link|route|rule|neigh)\s+(?:add|del|delete|replace|set|flush|change)\b",
    # v4: -nvL / -S / --list, iptables-save, nft list|describe|monitor are reads
    r"(?-i:^ip6?tables(?:-legacy|-nft)?\s(?!(?:.*\s)?(?:-[a-zA-Z]*[LS][a-zA-Z]*|--list\S*)(?:\s|$)))", r"^ip6?tables(?:-legacy|-nft)?-restore\b",
    r"^nft\s+(?!(?:-\S+\s+)*(?:list|describe|monitor)\b)\S",
    r"^(?:zfs|zpool)\s+(?:create|destroy|set|rollback|rename|import|export|attach|detach|replace|add|remove|offline|online)\b",
    r"^(?:lv|vg|pv)(?:create|remove|extend|reduce|resize|rename|change)\b", r"^mkfs\S*\b", r"^(?:mdadm)\s+--(?:create|grow|add|remove|fail|stop)\b",
    # v4: wget writes a file unless it prints to stdout (-qO-) or only checks (--spider)
    r"(?-i:^wget\b(?!.*(?:\s-[A-Za-z]*O\s*-(?:\s|$)|\s--output-document[= ]-(?:\s|$)|\s-[A-Za-z]*O\s*/dev/null|\s--spider\b)))",
    r"^(?:timedatectl|hostnamectl|localectl)\s+(?:-\S+\s+)*set-",
    r"^ufw\s+(?:--\S+\s+)*(?:allow|deny|reject|limit|delete|insert|enable|disable|reset|reload|default|route)\b",
    r"^firewall-cmd\b.*--(?:add|remove|reload|complete-reload|set|new|delete|change)",
    # v4: Proxmox (status/list/config are reads; pct exec / qm guest exec are classified by what they run)
    r"^pct\s+(?!(?:list|status|config|pending|listsnapshot|df|cpusets|help|exec)\b)\S",
    r"^qm\s+(?!(?:list|status|config|pending|listsnapshot|showcmd|help|guest\s+(?:exec\b|exec-status\b"
    r"|cmd\s+\S+\s+(?:ping|info|get-\S+|network-get-interfaces)\b)))\S",
    r"^pvesh\s+(?:create|set|delete|post|put)\b", r"^pvesm\s+(?:add|set|remove|alloc|free|import|prune-backups)\b",
    r"^(?:vzdump|qmrestore|pveupdate|pveupgrade)\b", r"^pveam\s+(?:download|remove)\b",
    r"^ha-manager\s+(?:add|set|remove|migrate|relocate|crm-command)\b",
    r"^kubectl\s+(?:-\S+\s+(?:\S+\s+)?)*(?:delete|apply|create|replace|patch|edit|scale|set|label|annotate|drain|cordon"
    r"|uncordon|taint|exec|cp|run|expose|autoscale|rollout\s+(?:restart|undo|pause|resume))\b",
    r"^helm\s+(?:install|upgrade|uninstall|delete|rollback)\b",
    r"^composer\s+(?:-\S+\s+)*(?:install|i|update|u|upgrade|require|remove|rm|dump-autoload|dumpautoload|create-project"
    r"|run-script|run|exec|self-update|selfupdate|clear-cache|global|reinstall|bump)\b",
    r"^php\S*\s+(?:-\S+\s+)*(?:\S+/)?artisan\s+(?!(?:list|help|about|env|inspire|route:list|migrate:status|schedule:list"
    r"|queue:monitor|db:show|db:table|model:show|event:list|channel:list|-V|--version)(?:\s|$))\S",
    r"^curl\b.*(?:(?-i:\s-[A-Za-z]*X)\s*['\"]?(?:POST|PUT|DELETE|PATCH)\b|--request[\s=]+['\"]?(?:POST|PUT|DELETE|PATCH)\b"
    r"|(?-i:\s-[A-Za-z]*[dFT])(?=[\s'\"@]|$)|\s(?:--data\S*|--form\S*|--upload-file|--json)\b"
    r"|(?:(?-i:\s-[A-Za-z]*[oO])|\s--output)\s*(?!/dev/null\b|-(?:\s|$))[^\s-])",       # v3: glued -sX POST, -sd, -o file
    r"^(?:mysql|mariadb|psql|sqlite3)\b.*(?:\s-e\s|\s-c\s|--execute)\s*['\"]?.*\b(?:INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|ALTER\s+TABLE|DROP\s+(?:TABLE|DATABASE|INDEX|USER)|CREATE\s+(?:TABLE|DATABASE|INDEX|USER)|TRUNCATE\s|GRANT\s|REVOKE\s|SET\s+GLOBAL)",
    r"^(?:\S+/)?\S*(?:install|deploy|apply|rollback|promote|migrate)\S*\.(?:py|sh|ps1|pl)\b",
    r"^(?:python3?|bash|sh|perl)\s+\S*(?:install|deploy|apply|rollback|promote|migrate)\S*\.(?:py|sh|pl)\b",
]
PATTERN_RE = [re.compile(p, re.IGNORECASE) for p in PATTERNS]
CURL_WRITE_RE = next(rx for rx in PATTERN_RE if rx.pattern.startswith(r"^curl"))     # applied to "curl <args>"
WGET_WRITE_RE = next(rx for rx in PATTERN_RE if "^wget" in rx.pattern[:20])
STDIN_SCRIPT_RE = re.compile(r"(?:^|\s)(?:(?:ba|z|da|k)?sh\s+-s\b|(?:ba|z)?sh\s*$|python3?(?:\s+-[A-Za-z]+)*\s+-(?:\s|$)|perl\s+-(?:\s|$)|(?:mysql|psql|mariadb|sqlite3)\b(?!.*\s-e\s))")
REDIRECT_RE = re.compile(r"(?:(?<![<>&\d-])\d?|&)>{1,2}\|?\s*(?!/dev/null\b|&\d|&-)[^\s&|;)]")   # v5: &> too
CALL_GATE_RE = re.compile(REMOTE_TOOLS, re.IGNORECASE)
# a cheap gate before recursive parsing: ssh family, PowerShell remoting, UNC paths (v4)
WIN_REMOTE_GATE = (r"invoke-command|\bicm\b|enter-pssession|\betsn\b|\\\\[\w.-]+|//[\w.-]+/|-computername|-cn\b|-cimsession"
                   r"|psexec|paexec|winrs|wmic|start-process|schtasks|new-psdrive|shutdown")       # v5: Windows remoting
RAW_REMOTE_RE = re.compile(REMOTE_TOOLS + "|" + WIN_REMOTE_GATE, re.IGNORECASE)
WIN_GATE_RE = re.compile(WIN_REMOTE_GATE, re.IGNORECASE)
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
AWKS = {"awk", "gawk", "mawk", "nawk"}
SQL_CLIENTS = {"mysql", "mariadb", "psql", "sqlite3", "clickhouse-client"}
PY_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|py)$")
INTERACTIVE_RE = re.compile(r"sudo\s+-[is]\w*|sudo\s+(?:-\S+\s+)*(?:su|bash|sh)(?:\s+-l?)?(?:\s+\S+)?|su(?:\s+-l?)?(?:\s+\S+)?"
                            r"|(?:exec\s+)?(?:ba|z|da|k)?sh(?:\s+-l)?")
PY_MUTATE_RE = re.compile(
    r"\b(?:os\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|mkdir|makedirs|chmod|chown|lchown|symlink|link"
    r"|truncate|utime|kill|killpg)|shutil\.(?:rmtree|move|copy\w*|chown|unpack_archive|make_archive))\s*\("
    r"|\.(?:unlink|rmdir|mkdir|touch|write_text|write_bytes|symlink_to|hardlink_to|chmod)\s*\("
    r"|\bopen\s*\([^;\n]*?['\"][rbt]*[wax+][rbt+]*['\"]")
PATH_RENAME_RE = re.compile(r"\.rename\s*\(")            # v4: only with pathlib in the code (pandas .rename is a read)
PHP_MUTATE_RE = re.compile(r"\b(?:unlink|rmdir|rename|mkdir|chmod|chown|chgrp|copy|touch|symlink|link|file_put_contents"
                           r"|fwrite|fputs|ftruncate|move_uploaded_file)\s*\(|\bfopen\s*\([^)]*['\"](?:[wxac]|r\+)")
JS_MUTATE_RE = re.compile(r"\.(?:rm|rmdir|unlink|mkdir|rename|writeFile|appendFile|copyFile|cp|chmod|chown|symlink|truncate"
                          r"|createWriteStream)(?:Sync)?\s*\(")
RUBY_MUTATE_RE = re.compile(r"\b(?:File\.(?:delete|unlink|write|binwrite|rename|chmod|chown|symlink|link|truncate)"
                            r"|FileUtils\.\w+|Dir\.(?:mkdir|rmdir|delete|unlink)|IO\.(?:write|binwrite))\b"
                            r"|\b(?:File\.)?open\s*\([^)]*['\"][wa]")
UNC_RE = re.compile(r"(?:\\\\|//)([A-Za-z0-9_.-]+)[\\/]")
PS_REMOTING_RE = re.compile(r"(?i)(?:^|[\s;|&({])(invoke-command|icm|enter-pssession|etsn)(?=\s|$)")
PS_WRITE_RE = re.compile(r"(?i)(?:^|[\s;|&({])(copy-item|cpi|copy|xcopy|robocopy|move-item|mi|move|remove-item|ri|del|erase"
                         r"|rd|rmdir|set-content|sc|add-content|ac|new-item|ni|mkdir|md|out-file|rename-item|rni|clear-content"
                         r"|clc|set-item|si)(?=\s)([^;|\n]*)")
PS_COPY = {"copy-item", "cpi", "copy", "xcopy", "robocopy", "move-item", "mi", "move"}
PS_READ_RE = re.compile(r"(?i)^(?:(?:Get|Test|Select|Format|Measure|Where|Sort|Group|ConvertTo|ConvertFrom|Resolve|Compare"
                        r"|Find|Search|Write)-\w+|Out-String|Out-Host|hostname|whoami|ipconfig|systeminfo|\$\w+|=|%|\?"
                        r"|foreach|ForEach-Object|Where-Object)$")
PERL_MUTATE_RE = re.compile(r"\b(?:unlink|rmdir|rename|mkdir|chmod|chown|symlink|link|truncate|utime|kill)\s*(?:\(|\$|['\"]/|glob\b)"
                            r"|\bopen\b[^;]*?['\"]\s*(?:\+?>|\+<|\|)")
AWK_WRITE_RE = re.compile(r"\bprintf?\b[^;}]*?>")
EXEC_CALL_RE = re.compile(r"\b(?:system|popen|Popen|run|call|check_call|check_output|getoutput|getstatusoutput"
                          r"|exec(?:[lv]p?e?|Sync|File(?:Sync)?)?|spawn\w*|qx|shell_exec|passthru|proc_open)\s*(?=[({'\"])")
PY_EXTRA_RE = re.compile(r"(?<!stdout)(?<!stderr)\.write(?:lines)?\s*\(|\brequests\.(?:post|put|patch|delete)\s*\(|\.commit\s*\("
                         r"|\burlopen\s*\([^)]*(?:data=|method=)|\.execute\w*\s*\(\s*[rbuf]*['\"]\s*(?i:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE)")
LITERAL_RE = re.compile(r"[rRbBuUfF]{0,2}(\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*')")


def load_hosts(path: Path | None = None) -> dict[str, str]:
    """alias/IP -> canonical host id (lower-case). Raises OSError when no host table is configured."""
    path = path or DEFAULT_HOSTS
    if path is None:
        raise FileNotFoundError("no lock-guard host table configured")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    table = {}
    for canonical, names in data["hosts"].items():
        for name in [canonical, *names]:
            table[name.lower()] = canonical
    for vmid, canonical in (data.get("vmids") or {}).items():   # v4: Proxmox guest id -> host (pct/qm exec)
        if not str(vmid).startswith("_"):
            table[f"vmid:{vmid}"] = canonical
    return table


HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _strip_heredocs(command: str) -> str:
    """Drop heredoc bodies (file contents, not commands); the heredoc itself still feeds stdin.
    v4: only a << outside quotes starts a heredoc; one inside "..." belongs to the remote command."""
    out, delim, quote = [], None, None
    for line in command.split("\n"):
        if delim is not None:
            if line.strip() == delim:
                delim = None
            continue
        k = 0
        while k < len(line):
            c = line[k]
            if c == "\\" and quote != "'":
                k += 2
                continue
            if c in "'\"":
                quote = c if quote is None else (None if quote == c else quote)
            elif quote is None and c == "#" and (k == 0 or line[k - 1].isspace()):
                break                              # a comment: its apostrophes are not quotes
            elif quote is None and line.startswith("<<", k) and not line.startswith("<<<", k):
                match = HEREDOC_RE.match(line, k)
                if match:
                    delim = match.group(2)
                    line = line[:k] + " < __heredoc__ " + line[match.end():]
                    break
            k += 1
        out.append(line)
    return "\n".join(out)


def _tokens(command: str, ps: bool = False) -> list[str]:
    # v4: an unquoted newline ends a command (it was whitespace: "echo a<NL>ssh host rm x" hid the call)
    lexer = shlex.shlex(_strip_heredocs(command).replace("\\\n", " "), posix=True, punctuation_chars=";&|<>\n")
    lexer.whitespace_split = True
    lexer.whitespace = " \t\r"
    if ps:
        lexer.escape = ""                    # PowerShell: backslash is a path separator, not an escape
    try:
        tokens = list(lexer)
    except ValueError:                       # unbalanced quotes: fall back to a coarse split
        return command.split()
    # "|\n", "&&\n", ";\n": the newline only continues; a run of newlines is one separator
    return [t.replace("\n", "") or "\n" if "\n" in t and not t.strip(";&|<>\n") else t for t in tokens]


def _pipeline(text: str) -> list[tuple[bool, list[str]]]:
    """[(stdin_fed, words)] per simple command: fed by a pipe, a < file, a heredoc or a <<< string."""
    segs, cur, piped = [], [], False
    for tok in _tokens(text) + [";"]:
        if tok in SEPARATORS:
            if cur:
                segs.append((piped or any(t.startswith("<") for t in cur), cur))
            cur, piped = [], tok == "|"
        else:
            cur.append(tok)
    return segs


def _segments(text: str) -> list[list[str]]:
    return [words for _, words in _pipeline(text)]


def _rejoin(tokens: list[str]) -> str:
    """Tokens back to shell text. v5: every word is quoted (a|b, $x, * stay one word); separators, redirections
    and their targets stay bare so that the text is re-parsed and REDIRECT_RE still sees `> $S/x`."""
    out, prev = [], ""
    for t in tokens:
        bare = t and (t in SEPARATORS or re.fullmatch(r"\d*[<>]+[&|]?\d*|&>>?", t)
                      or re.fullmatch(r"\d*[<>]+[|]?|&>>?", prev or "x"))
        out.append(t if bare else shlex.quote(t))
        prev = t
    return " ".join(out)


def _prog_name(tok: str) -> str:
    """Program name, lower-case, without dir and .exe: /usr/bin/ssh, C:\\...\\OpenSSH\\ssh.exe, $(ssh -> ssh."""
    name = re.split(r"[/\\]", re.sub(r"^(?:[A-Za-z_]\w*=)?[$(`{]+", "", tok))[-1].lower()
    if re.match(r"^[a-z]:", name):           # C:WindowsSystem32OpenSSHssh.exe: a POSIX lexer ate the backslashes
        match = re.search(REMOTE_TOOLS + r"(?:\.exe)?$", name)
        name = match.group(0) if match else name
    return name[:-4] if name.endswith(".exe") else name


def _prefix_len(words: list[str], runners: bool = False) -> int:
    """How many leading words are prefixes (PREFIXES table, VAR=x) before the real command word."""
    i = 0
    while i < len(words):
        name = "(" if words[i] in ("(", "{") else _prog_name(words[i])
        if name in PREFIXES and (runners or name not in RUNNERS):
            valued, i = PREFIXES[name], i + 1
            while i < len(words) and (words[i].startswith("-") or re.fullmatch(r"[A-Za-z_]\w*=.*|\d+(?:\.\d+)?[smhd]?", words[i])):
                if words[i] == "--":                # wsl -- ssh, sudo -- cmd
                    i += 1
                    break
                i += 2 if words[i] in valued else 1
        elif re.fullmatch(r"[A-Za-z_]\w*=.*", words[i]):
            i += 1
        else:
            break
    return i


def _strip_prefix(words: list[str]) -> list[str]:
    """Drop sudo/env/timeout/nice/setsid/sshpass/do/then/VAR=x... before the real command word."""
    return words[_prefix_len(words):]


def _stdin_interpreter(words: list[str]) -> bool:
    """True when the command is a shell/interpreter/SQL client that reads its program from stdin."""
    name, args, k = _prog_name(words[0]), [], 1
    while k < len(words):
        if words[k][:1] in "<>":
            k += 1 if words[k].endswith("&") else 2
            continue
        args.append(words[k])
        k += 1
    if PY_RE.match(name):
        args = [a for n, a in enumerate(args) if a not in ("-X", "-W") and (n == 0 or args[n - 1] not in ("-X", "-W"))]
    positional = [a for a in args if not a.startswith("-") or a == "-"]
    script = not positional or positional[0] == "-"
    if name in SHELLS:
        return _code_arg(args, r"-[A-Za-z]*c[A-Za-z]*") is None and (script or "-s" in args)
    if PY_RE.match(name):
        return _code_arg(args, r"-[A-Za-z]*c") is None and "-m" not in args and script
    if name in ("perl", "ruby"):
        return _code_arg(args, r"-[A-Za-z]*[eE]") is None and script
    if name in ("php", "node", "nodejs"):
        return not any(re.fullmatch(r"-[rep]|--eval|--print|-f", a) for a in args) and script
    if name in ("at", "batch"):
        return not _has(args, "-l", "-c", "-d", "-r")
    if name in SQL_CLIENTS:
        return True                                 # v6: stdin of a SQL client is SQL, with or without -e
    return False


def _unquote(literal: str) -> str:
    q = 3 if literal[:3] in ('"""', "'''") else 1
    return re.sub(r"\\(.)", r"\1", literal[q:-q])


def _exec_snippets(code: str) -> list[str]:
    """Shell commands that python/perl/awk code hands to system()/subprocess/qx/backticks/pipes."""
    out = [m.group(1) for m in re.finditer(r"`([^`]*)`", code)]
    for m in EXEC_CALL_RE.finditer(code):
        j, args, listed = m.end(), [], False
        depth = 1 if code[j] in "({" else 0
        j += depth
        while j < len(code):
            lit = LITERAL_RE.match(code, j)
            if lit:
                args.append(_unquote(lit.group(1)))
                j = lit.end()
                if not depth:
                    break                      # system "cmd" / qx'cmd' without parentheses
                continue
            c = code[j]
            listed = listed or (c == "[" and not args)
            depth += (c in "([{") - (c in ")]}")
            if depth <= 0:
                break
            j += 1
        if args:
            out.append(shlex.join(args) if listed else " ".join(args))   # ['ssh','h','rm -r x'] keeps its words
    out += re.findall(r"\|\s*\"([^\"]+)\"", code) + re.findall(r"\"([^\"]+)\"\s*\|\s*getline", code)   # awk pipes
    return out


def _code_arg(args: list[str], flag: str, valued: tuple = ()) -> int | None:
    """Index of the code after a -c/-e style flag; options only are scanned (a script file ends the search)."""
    k = 0
    while k < len(args) and args[k].startswith(("-", "+")) and args[k] not in ("-", "--", "-m"):
        if re.fullmatch(flag, args[k]):
            return k + 1 if k + 1 < len(args) else None
        k += 2 if args[k] in valued else 1
    return None


def _guest_exec(name: str, args: list[str]) -> tuple[str, list[str]] | None:
    """Proxmox `pct exec <vmid> -- cmd` / `qm guest exec <vmid> [opts] -- cmd`: (vmid, cmd words)."""
    if name == "pct" and args[:1] == ["exec"] and len(args) > 2:
        vmid, rest = args[1], args[2:]
    elif name == "qm" and args[:2] == ["guest", "exec"] and len(args) > 3:
        vmid, rest = args[2], args[3:]
    else:
        return None
    rest = rest[rest.index("--") + 1:] if "--" in rest else [a for a in rest if not a.startswith("--")]
    return (vmid, rest) if rest else None


def _embedded(words: list[str]) -> tuple[str, list[str], str]:
    """What a wrapper command runs: (label, shell snippets, direct change found in its code)."""
    if not words:
        return "", [], ""
    name, args = _prog_name(words[0]), words[1:]
    if name in SHELLS:
        k = _code_arg(args, r"-[A-Za-z]*c[A-Za-z]*", ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"))
        return (f"{name}-c", [args[k]], "") if k is not None else ("", [], "")
    if name in ("su", "runuser"):
        k = next((k for k, t in enumerate(args[:-1]) if t in ("-c", "--command")), None)
        return (f"{name}-c", [args[k + 1]], "") if k is not None else ("", [], "")
    if name == "eval":
        return "eval", [" ".join(args)], ""
    if name == "cmd":
        k = next((k for k, t in enumerate(args) if t.lower() in ("/c", "/k")), None)
        return ("cmd", [" ".join(args[k + 1:])], "") if k is not None else ("", [], "")
    if name in ("powershell", "pwsh"):
        k = 0
        while k < len(args):
            t = args[k].lower()
            if t in ("-e", "-ec") or t.startswith("-enc"):
                try:
                    return name, [base64.b64decode(args[k + 1]).decode("utf-16-le")], ""
                except (IndexError, ValueError):
                    return name, [], "opaque-encoded-command"
            if t == "-c" or t.startswith("-com") or not t.startswith("-"):
                return name, [" ".join(args[k + t.startswith("-"):])], ""
            if t.startswith("-f"):
                return "", [], ""                # -File script.ps1
            k += 2 if t.startswith(("-ex", "-ep", "-w", "-v", "-in", "-ou", "-of", "-con", "-se")) else 1
        return "", [], ""
    if PY_RE.match(name):
        k = _code_arg(args, r"-[A-Za-z]*c", ("-X", "-W"))
        if k is None:
            return "", [], ""
        found = PY_MUTATE_RE.search(args[k]) or ("Path" in args[k] and PATH_RENAME_RE.search(args[k]))
        return "python-c", _exec_snippets(args[k]), found.group(0).strip() if found else ""
    for label, names, flag, rx in (("php-r", ("php",), r"-r", PHP_MUTATE_RE),                # v4
                                   ("node-e", ("node", "nodejs"), r"-e|--eval|-p|--print", JS_MUTATE_RE),
                                   ("ruby-e", ("ruby",), r"-[A-Za-z]*e", RUBY_MUTATE_RE)):
        if name in names:
            k = _code_arg(args, flag)
            if k is None:
                return "", [], ""
            found = rx.search(args[k])
            return label, _exec_snippets(args[k]), found.group(0).strip() if found else ""
    guest = _guest_exec(name, args)
    if guest:
        return f"{name}-exec", [_rejoin(guest[1])], ""
    if name == "watch":
        k = 0
        while k < len(args) and args[k].startswith("-"):
            k += 2 if args[k] in PREFIXES["watch"] else 1
        return ("watch", [" ".join(args[k:])], "") if k < len(args) else ("", [], "")
    if name == "perl":
        k = _code_arg(args, r"-[A-Za-z]*[eE]")
        if k is None:
            return "", [], ""
        inplace = any(re.fullmatch(r"-[A-Za-z]*i\S*", a) and not a.startswith(("-M", "-m", "-I")) for a in args[:k])
        found = PERL_MUTATE_RE.search(args[k])
        return "perl-e", _exec_snippets(args[k]), "in-place-edit" if inplace else (found.group(0).strip() if found else "")
    if name in AWKS:
        k = 0
        while k < len(args) and args[k].startswith("-") and args[k] != "--":
            if args[k] in ("-f", "-E") or args[k].startswith("--file"):
                return "", [], ""                # program in a file
            if args[k] in ("-i", "-iinplace") and "inplace" in args[k:k + 2] + [args[k][2:]]:
                return "awk", [], "in-place-edit"
            k += 2 if args[k] in ("-F", "-v", "-i", "-l") else 1
        k += k < len(args) and args[k] == "--"
        if k >= len(args):
            return "", [], ""
        return "awk", _exec_snippets(args[k]), "print-to-file" if AWK_WRITE_RE.search(args[k]) else ""
    if name == "find":
        snippets = []
        for k, t in enumerate(args):
            if t in ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls"):
                return "find", [], t[1:]
            if t in ("-exec", "-execdir", "-ok", "-okdir"):
                end = next((m for m in range(k + 1, len(args)) if args[m] in (";", "\\;", "+")), len(args))
                snippets.append(" ".join(args[k + 1:end]))
        return ("find-exec", snippets, "") if snippets else ("", [], "")
    if name == "xargs":
        k = 0
        while k < len(args) and args[k].startswith("-"):
            k += 2 if args[k] in ("-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a") else 1
        return ("xargs", [" ".join(args[k:])], "") if k < len(args) else ("", [], "")
    return "", [], ""


def _scan_substitutions(command: str, ps: bool = False) -> tuple[list[str], str]:
    """(bodies of $(...), `...`, <(...), >(...) that the shell runs outside single quotes,
    the command with each of them replaced by __subst__ so that its words stay one word)."""
    out, masked, i, quote = [], [], 0, None
    while i < len(command):
        c = command[i]
        if c == "\\" and quote != "'" and not ps:
            masked.append(command[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c if quote is None else (None if quote == c else quote)
        elif quote != "'" and command.startswith("$((", i):
            depth, j = 2, i + 3                    # $(( arithmetic )) is not a command
            while j < len(command) and depth:
                depth += (command[j] == "(") - (command[j] == ")")
                j += 1
            masked.append("__subst__")
            i = j
            continue
        elif quote != "'" and command.startswith(("$(", "<(", ">("), i):   # v5: process substitution too
            depth, j = 1, i + 2
            while j < len(command) and depth:
                depth += (command[j] == "(") - (command[j] == ")")
                j += 1
            out.append(command[i + 2:j - 1])
            masked.append("__subst__")
            i = j
            continue
        elif quote != "'" and c == "`" and not ps:
            j = command.find("`", i + 1)
            j = len(command) if j < 0 else j
            out.append(command[i + 1:j])
            masked.append("__subst__")
            i = j + 1
            continue
        masked.append(c)
        i += 1
    return out, "".join(masked)


def _substitutions(command: str, ps: bool = False) -> list[str]:
    return _scan_substitutions(command, ps)[0]


def _drop_calls(text: str) -> str:
    """The text without its nested ssh/scp/sftp calls: those are classified for their own host.
    v4: a copy with no remote target (rsync a b, scp vm:/x /tmp) stays: it writes onto this host."""
    tokens, kept, i = _tokens(text), [], 0
    while i < len(tokens):
        if re.fullmatch(REMOTE_TOOLS, _prog_name(tokens[i])) and _command_position(tokens, i):
            j = i
            while j < len(tokens) and tokens[j] not in SEPARATORS and tokens[j][:1] not in "<>":
                j += 1                         # a redirect after it runs on this host and stays
            if _prog_name(tokens[i]) in SSH_TOOLS or parse_remote_calls(_rejoin(tokens[i:j]), {}):
                i = j
                continue
        kept.append(tokens[i])
        i += 1
    return _rejoin(kept)


def _guest_calls(remote: str, hosts: dict[str, str]) -> tuple[list[dict], str]:
    """v4: pct exec / qm guest exec on a hypervisor lock the guest when hosts.json maps its vmid;
    an unmapped vmid stays in the hypervisor's own command (lock on the hypervisor)."""
    tokens, kept, calls, i = _tokens(remote), [], [], 0
    while i < len(tokens):
        j = i
        while j < len(tokens) and tokens[j] not in SEPARATORS:
            j += 1
        seg = _strip_prefix(tokens[i:j])
        guest = _guest_exec(_prog_name(seg[0]), seg[1:]) if seg else None
        if guest and hosts.get(f"vmid:{guest[0]}"):
            inner = _rejoin(guest[1])
            reason = remote_is_mutating(inner)
            calls.append(_call(f"vmid:{guest[0]}", hosts, inner, reason and f"{_prog_name(seg[0])}-exec:{reason}", "guest"))
        else:
            kept += tokens[i:j]
        kept += tokens[j:j + 1]
        i = j + 1
    return (calls, _rejoin(kept)) if calls else ([], remote)


def _host_of(dest: str) -> str:
    dest = dest.split("@", 1)[-1]
    if dest.startswith("[") and "]" in dest:
        return dest[1:dest.index("]")]
    return dest.split(":", 1)[0] if re.match(r"^[^/\\]+:", dest) else dest


def _is_remote_path(arg: str) -> bool:
    """host:path or user@host:path; a Windows drive (C:/x, D:\\x) is local."""
    return bool(re.match(r"^(?:[^@/\\\s]+@)?(?:\[[^\]]+\]|[A-Za-z0-9_.-]{2,}):", arg))


# ---------------------------------------------------------------------------------------------------------------
# v5: the REMOTE side is an allowlist. A simple command is a read only when READ says so; everything else (unknown
# programs, scripts, $VAR as a command, editors, schedulers...) is a change. FIRST_WORD/PATTERNS only name the reason.
# ---------------------------------------------------------------------------------------------------------------
def _pos(args: list[str], valued: tuple | set = ()) -> list[str]:
    """Positional arguments, skipping options and the values of `valued` options."""
    out, k = [], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            return out + args[k + 1:]
        if a.startswith("-") and len(a) > 1:
            k += 2 if a in valued else 1
            continue
        out.append(a)
        k += 1
    return out


def _verb(args: list[str], valued: tuple | set = ()) -> str:
    return (_pos(args, valued) or [""])[0].lower()


def _has(args: list[str], *flags: str) -> bool:
    """A long flag (prefix, --x=v) or a short letter inside a bundle (-nvL has L)."""
    for a in args:
        for f in flags:
            if f.startswith("--") and (a == f or a.startswith(f + "=") or (f.endswith("*") and a.startswith(f[:-1]))):
                return True
            if len(f) == 2 and f[0] == "-" and re.fullmatch(r"-[A-Za-z0-9]+", a) and f[1] in a[1:]:
                return True
    return False


def _sql_read(sql: str) -> bool:
    statements = [s.strip() for s in re.split(r";", sql) if s.strip()]
    # v6: psql metas only for listing (\d…, \l, \conninfo, \x, \timing; not \o \w \g \i \! \copy \e \set);
    # sqlite3 dot-commands only for listing (.tables, .schema, …; not .shell .system .output .once .import)
    return bool(statements) and all(re.match(r"(?is)(?:SELECT|SHOW|DESC(?:RIBE)?|EXPLAIN|USE\s|SET\s+(?:SESSION\s+|LOCAL\s+)?"
                                              r"(?!GLOBAL)\w+\s*=|WITH\s|\\(?:d[A-Za-z+]*|l\+?|conninfo|x|timing|encoding|\?|h)"
                                              r"(?![A-Za-z])|\.(?:tables|schema|indexes|indices|databases|dbinfo|headers|mode"
                                              r"|width|show|stats)(?![A-Za-z]))", s) for s in statements) and not re.search(
        r"(?i)\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|RENAME|REPLACE|MERGE|LOAD|CALL|LOCK|OUTFILE"
        r"|DUMPFILE|COPY|VACUUM|REINDEX|CLUSTER|SET\s+GLOBAL|FLUSH|KILL|SHUTDOWN|PURGE|OPTIMIZE|REPAIR|INSTALL|UNINSTALL)\b", sql)


def _ip_read(args: list[str]) -> bool:
    if any(a in ("-b", "-batch", "--batch", "-force") or a.startswith("-batch") for a in args):
        return False                                # v6: a batch file is an opaque list of commands
    pos = _pos(args, ("-n", "-netns", "-f", "-family", "-b", "-batch", "-rc", "-rcvbuf"))
    if pos[:2] == ["netns", "exec"]:
        return False                                # handled by _embedded
    return len(pos) < 2 or pos[1] in ("show", "list", "ls", "lst", "sh", "get", "save" if pos[0] == "netns" else "show",
                                      "identify", "pids", "monitor")


def _docker_read(args: list[str]) -> bool:
    pos = _pos(args, ("-H", "--host", "--context", "-c", "--config", "-l", "--log-level", "-f", "--file", "-p", "--project-name"))
    verb = " ".join(pos[:2])
    return bool(pos) and (pos[0] in ("ps", "logs", "inspect", "images", "stats", "top", "port", "version", "info", "events",
                                    "diff", "history", "search") or verb in (
        "image ls", "image inspect", "image history", "container ls", "container inspect", "container logs",
        "container top", "container port", "container stats", "network ls", "network inspect", "volume ls",
        "volume inspect", "system df", "system info", "context ls", "compose ps", "compose logs", "compose config",
        "compose ls", "compose images", "compose top", "compose version", "buildx ls")) and (pos[0] != "stats" or _has(args, "--no-stream"))


def _ethtool_read(args: list[str]) -> bool:
    return not (_has(args, "-s", "-K", "-G", "-A", "-C", "-L", "-E", "-N", "-U", "-X", "-W", "-r", "-p", "-f", "-D")
                or any(re.match(r"--(?:set|change|flash|reset|config|features=|offload)", a) for a in args))


def _vtysh_read(args: list[str]) -> bool:
    cmds = [args[k + 1] for k, a in enumerate(args[:-1]) if a in ("-c", "--command")]
    return bool(cmds) and not _has(args, "-f", "-b", "--boot", "--inputfile") and all(
        re.match(r"\s*(?:do\s+)?(?:show|sh)\b", c, re.I) for c in cmds)


# ---------------------------------------------------------------------------------------------------------------
# v6 (review round 5): programs that can run a command or write a file through their OWN flags get
# a flag ALLOWLIST (an unknown flag = a change); environment prefixes are judged too.
# ---------------------------------------------------------------------------------------------------------------
SAFE_ENV = {"LC_ALL", "LANG", "LANGUAGE", "LC_CTYPE", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
            "TZ", "COLUMNS", "LINES", "TERM", "NO_COLOR", "SYSTEMD_COLORS"}   # locale/format only: they cannot run code
PAGER_ENV = {"PAGER", "GIT_PAGER", "SYSTEMD_PAGER", "MANPAGER", "PSQL_PAGER", "BAT_PAGER"}   # allowed only as =cat / empty
DANGEROUS_ENV_RE = re.compile(r"^(?:PATH|LD_\w+|DYLD_\w+|\w*PAGER|LESS\w*|GIT_\w+|BASH_ENV|ENV|PROMPT_COMMAND|PS4|IFS|SHELLOPTS"
                              r"|BASHOPTS|PYTHON\w*|PERL5?\w*|NODE_\w+|RUBY\w*|EDITOR|VISUAL|MYSQL_\w+|PSQLRC|PG\w+|CURL_\w+"
                              r"|WGETRC|SYSTEMD_\w+|SUDO_\w+|SSH_ASKPASS\w*|ZDOTDIR|INPUTRC|TMPDIR|HOME|XDG_CONFIG_HOME"
                              r"|RSYNC_RSH|CVS_RSH|SVN_SSH|BORG_RSH)$")


def _env_reason(words: list[str]) -> str | None:
    """`VAR=… cmd` is a change unless VAR is locale/format-only (SAFE_ENV) or a pager set to cat; a bare assignment
    is a change only for variables that steer later commands (PATH, LD_*, pagers, GIT_*…); env -S runs a string."""
    n = _prefix_len(words)
    has_cmd = n < len(words)
    k = 0
    while k < n:
        w = words[k]
        if _prog_name(w) == "env":
            j = k + 1
            while j < n and (words[j].startswith("-") or "=" in words[j]):
                if re.fullmatch(r"-[A-Za-z]*S.*|--split-string(?:=.*)?", words[j]):
                    return "env-split-string"
                unset = words[j + 1] if words[j] in ("-u", "--unset") and j + 1 < n else (
                    words[j][2:] if words[j].startswith("-u") else words[j].partition("=")[2] if words[j].startswith("--unset=") else "")
                if unset and DANGEROUS_ENV_RE.match(unset):
                    return f"env-unset:{unset}"            # v7: env -u PATH
                j += 1
        match = re.fullmatch(r"([A-Za-z_]\w*)=(.*)", w, re.S)
        if match:
            name, value = match.groups()
            if not (name in PAGER_ENV and value.strip("'\"") in ("", "cat")):
                if has_cmd and name not in SAFE_ENV:
                    return f"env-prefix:{name}"
                if not has_cmd and DANGEROUS_ENV_RE.match(name):
                    return f"env-assign:{name}"
        k += 1
    return None


def _options(args: list[str], valued_short: str = "", valued_long: set | tuple = (), glued_only: str = "",
             glued_digits: str = "") -> tuple[list, list]:
    """([(option, value)], positional): short bundles expanded (-sXDELETE -> -s, -X DELETE), --opt=value split,
    -5 kept as ('-#', '-5'). `glued_only` letters take only a glued value (mysql -psecret, perl -l0)."""
    opts, pos, k = [], [], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            pos += args[k + 1:]
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, val = a.partition("=")
            if not eq and name in valued_long and k + 1 < len(args):
                val, k = args[k + 1], k + 1
            opts.append((name, val))
        elif re.fullmatch(r"-\d+", a):
            opts.append(("-#", a))
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in glued_digits:                     # perl -l / -0: only digits belong to the flag (-lane)
                    digits = re.match(r"(?:x[0-9A-Fa-f]+|\d*)", a[j + 1:]).group(0)
                    opts.append(("-" + ch, digits))
                    j += 1 + len(digits)
                    continue
                if ch in glued_only:
                    opts.append(("-" + ch, a[j + 1:]))
                    break
                if ch in valued_short:
                    val = a[j + 1:]
                    if not val and k + 1 < len(args):
                        val, k = args[k + 1], k + 1
                    opts.append(("-" + ch, val))
                    break
                opts.append(("-" + ch, ""))
                j += 1
        else:
            pos.append(a)
        k += 1
    return opts, pos


def _known(opts: list, short_ok: str, long_ok: set | tuple) -> bool:
    return all((name in long_ok) if name.startswith("--") else (name == "-#" and "#" in short_ok) or
               (name != "-#" and name[1] in short_ok) for name, _ in opts)


GIT_SAFE_CONFIG = {"safe.directory", "color.ui", "color.status", "color.diff", "color.branch", "core.quotepath",
                   "core.abbrev", "column.ui", "log.date", "log.decorate", "log.showsignature", "diff.renames",
                   "diff.noprefix", "grep.linenumber", "advice.detachedhead", "status.short", "status.branch"}
GIT_SHORT = "pPsSuvqnalrtwzbcdmkMCRBDNxXEHIFGLeohiAUTWyY0123456789#"        # no -O (grep: open files in a pager)
GIT_VALUED_SHORT = "nSGLefAB"
GIT_VALUED_LONG = {"--format", "--pretty", "--since", "--after", "--until", "--before", "--author", "--committer", "--grep",
                   "--max-count", "--skip", "--date", "--diff-filter", "--decorate-refs", "--stat-width", "--sort",
                   "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--exclude", "--glob",
                   "--max-depth", "--encoding", "--type", "--default", "--match", "--candidates", "--depth", "--jobs",
                   "--shallow-since", "--deepen", "--negotiation-tip"}
GIT_LONG = set("""--oneline --graph --decorate --decorate-refs --decorate-refs-exclude --no-decorate --all --branches --tags
--remotes --stat --shortstat --numstat --name-only --name-status --format --pretty --abbrev-commit --no-abbrev-commit --abbrev
--no-abbrev --since --after --until --before --author --committer --grep --invert-grep --all-match --regexp-ignore-case
--max-count --skip --max-parents --min-parents --merges --no-merges --first-parent --follow --reverse --date --date-order
--topo-order --author-date-order --relative-date --left-right --cherry-pick --cherry-mark --cherry --boundary --source --no-walk
--do-walk --simplify-by-decoration --full-history --dense --sparse --ancestry-path --patch --no-patch --patch-with-stat --raw
--summary --dirstat --minimal --patience --histogram --diff-algorithm --word-diff --word-diff-regex --color --no-color
--color-moved --color-words --ignore-space-change --ignore-all-space --ignore-blank-lines --ignore-space-at-eol
--ignore-cr-at-eol --ignore-submodules --unified --function-context --exit-code --quiet --check --cached --staged --no-index
--relative --no-relative --text --binary --full-index --no-renames --find-renames --find-copies --find-copies-harder
--diff-filter --src-prefix --dst-prefix --no-prefix --line-prefix --stat-width --stat-name-width --stat-count
--compact-summary --submodule --short --branch --porcelain --long --verbose --untracked-files --ignored --ahead-behind
--no-ahead-behind --renames --no-renames --column --no-column --show-stash --null --show-signature --notes --no-notes
--show-notes --expand-tabs --no-expand-tabs --mailmap --use-mailmap --no-mailmap --encoding --log-size --show-linear-break
--count --objects --in-commit-order --not --glob --exclude --reflog --walk-reflogs --show-current --list --contains
--no-contains --merged --no-merged --points-at --sort --heads --refs --symref --get-url --line-number --ignore-case
--word-regexp --fixed-strings --extended-regexp --perl-regexp --basic-regexp --files-with-matches --files-without-match
--only-matching --max-depth --others --modified --deleted --stage --exclude-standard --full-name --abbrev-ref --symbolic
--symbolic-full-name --show-toplevel --show-prefix --show-cdup --git-dir --git-common-dir --is-inside-work-tree
--is-bare-repository --verify --always --dirty --match --candidates --exact-match --line-porcelain --incremental
--show-email --show-name --show-number --root --recursive --full-tree --batch --batch-check --batch-all-objects --unordered
--buffer --follow-symlinks --help --version --get --get-all --get-regexp --show-origin --show-scope --global --system
--local --type --default --name-only --format --points-at --remote --show-pulls --remerge-diff --no-ext-diff
--no-textconv --no-color-moved --default-prefix --no-optional-locks --stdin-packs --progress --no-progress""".split())
GIT_FETCH_LONG = {"--all", "--prune", "--prune-tags", "--tags", "--no-tags", "--dry-run", "--verbose", "--quiet", "--depth",
                  "--deepen", "--shallow-since", "--shallow-exclude", "--progress", "--no-progress", "--multiple", "--jobs",
                  "--no-recurse-submodules", "--negotiation-tip", "--show-forced-updates", "--no-show-forced-updates",
                  "--ipv4", "--ipv6", "--append", "--atomic", "--no-write-fetch-head", "--write-fetch-head"}
GIT_READ_VERBS = {"log", "status", "diff", "show", "rev-parse", "describe", "ls-files", "ls-tree", "ls-remote", "blame",
                  "shortlog", "grep", "cat-file", "version", "help", "count-objects", "whatchanged", "name-rev", "rev-list",
                  "merge-base", "for-each-ref", "show-ref", "var", "check-ignore", "check-attr", "diff-tree", "diff-index",
                  "diff-files", "show-branch", "cherry"}


def _git_read(args: list[str]) -> bool:
    k = 0
    while k < len(args) and args[k].startswith("-"):          # global options: an allowlist (no -c core.pager=…, -p)
        a = args[k]
        if a == "-C":
            k += 2
        elif a == "-c":
            if k + 1 >= len(args) or args[k + 1].split("=", 1)[0].lower() not in GIT_SAFE_CONFIG:
                return False
            k += 2
        elif a.split("=", 1)[0] in ("--git-dir", "--work-tree", "--namespace"):
            k += 1 if "=" in a else 2
        elif a in ("--no-pager", "-P", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs",
                   "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks", "--version", "--help", "--bare"):
            k += 1
        else:
            return False
    if k >= len(args):
        return True
    verb, rest = args[k], args[k + 1:]
    opts, pos = _options(rest, GIT_VALUED_SHORT, GIT_VALUED_LONG)
    if verb == "fetch":                                       # no refspec into a local branch, no --upload-pack
        return _known(opts, "pPtqvanj", GIT_FETCH_LONG) and not any(":" in p or p.startswith("+") for p in pos)
    if not _known(opts, GIT_SHORT, GIT_LONG):
        return False
    if verb in GIT_READ_VERBS:
        return True
    names = {o for o, _ in opts}
    if verb == "branch":
        return not names & {"-d", "-D", "-m", "-M", "-c", "-C", "-f", "-u", "--force"} and (
            not pos or bool(names & {"-l", "--list", "--contains", "--merged", "--no-merged", "--points-at"}))
    if verb == "tag":
        return not pos or bool(names & {"-l", "--list", "--contains", "--points-at", "-v", "--verify"})
    if verb == "remote":
        return not pos or pos[0] in ("show", "get-url")
    if verb in ("stash", "worktree", "submodule", "reflog", "notes"):
        return bool(pos) and pos[0] in ("list", "show", "status")   # v6: bare `git stash` = push
    if verb == "config":
        return bool(names & {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin"}) or len(pos) == 1
    return False


MYSQL_LONG = set("""--execute --host --user --port --database --socket --password --skip-column-names --column-names --batch
--silent --raw --table --vertical --xml --html --no-auto-rehash --skip-auto-rehash --default-character-set --protocol
--connect-timeout --ssl-ca --ssl-cert --ssl-key --ssl-mode --skip-ssl --unbuffered --verbose --version --help --compress
--quick --line-numbers --skip-line-numbers --column-type-info --show-warnings --binary-as-hex --skip-pager --no-beep
--safe-updates --i-am-a-dummy --login-path""".split())       # no --pager, --init-command, --defaults-file, --tee
PSQL_LONG = set("""--command --host --username --port --dbname --field-separator --record-separator --no-align --tuples-only
--expanded --no-psqlrc --quiet --no-password --password --list --version --help --csv --html --echo-queries --echo-hidden
--echo-all --echo-errors --field-separator-zero --record-separator-zero""".split())   # no --file/-f, --output/-o, --log-file
SQLITE_FLAGS = {"-readonly", "-header", "-noheader", "-csv", "-json", "-line", "-list", "-column", "-box", "-table",
                "-markdown", "-html", "-batch", "-bail", "-ascii", "-quote", "-tabs", "-safe", "-version", "-help", "-nofollow"}


def _sql_client_read(name: str, args: list[str]) -> bool:
    """v6: SQL client options are an allowlist; the SQL must be visible (-e/-c) and read-only."""
    if name == "sqlite3":
        k, pos = 0, []
        while k < len(args):
            if args[k] in ("-separator", "-newline", "-nullvalue"):
                k += 2
            elif args[k].startswith("-"):
                if args[k] not in SQLITE_FLAGS:
                    return False
                k += 1
            else:
                pos.append(args[k])
                k += 1
        return len(pos) > 1 and _sql_read(pos[1])
    if name == "psql":
        opts, _ = _options(args, "chUpdFRv", PSQL_LONG - {"--no-align", "--tuples-only", "--expanded", "--no-psqlrc", "--quiet",
                                                       "--no-password", "--password", "--list", "--version", "--help", "--csv",
                                                       "--html", "--echo-queries", "--echo-hidden", "--echo-all", "--echo-errors",
                                                       "--field-separator-zero", "--record-separator-zero"})
        if not _known(opts, "chUpdFRvAtxXqwWlVaeEnHz0", PSQL_LONG):
            return False
        sql = [v for o, v in opts if o in ("-c", "--command")]
        return all(_sql_read(s) for s in sql) if sql else any(o in ("-l", "--list", "-V", "--version", "--help") for o, _ in opts)
    opts, _ = _options(args, "ehuPDS", MYSQL_LONG - {"--skip-column-names", "--column-names", "--batch", "--silent", "--raw",
                                                     "--table", "--vertical", "--xml", "--html", "--no-auto-rehash",
                                                     "--skip-auto-rehash", "--skip-ssl", "--unbuffered", "--verbose", "--version",
                                                     "--help", "--compress", "--quick", "--line-numbers", "--skip-line-numbers",
                                                     "--column-type-info", "--show-warnings", "--binary-as-hex", "--skip-pager",
                                                     "--no-beep", "--safe-updates", "--i-am-a-dummy", "--password"}, glued_only="p")
    if not _known(opts, "NBsrtEXHAvVqwnCUiehuPDSp", MYSQL_LONG):
        return False
    sql = [v for o, v in opts if o in ("-e", "--execute")]
    return all(_sql_read(s) for s in sql) if sql else any(o in ("-V", "--version", "--help") for o, _ in opts)


def _sed_script_read(script: str) -> bool:
    """No w/W (write a file) and no e (run a command): as commands or as s///flags."""
    for match in re.finditer(r"s(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1([A-Za-z0-9]*)", script):
        if re.search(r"[wWe]", match.group(2)):
            return False
    rest = re.sub(r"[sy](.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[A-Za-z0-9]*", " ", script)
    rest = re.sub(r"/(?:\\.|[^/])*/|\\(.)(?:\\.|(?!\1).)*\1", " ", rest)          # address regexes
    return not re.search(r"(?<![A-Za-z_])[wWe](?![A-Za-z_])", rest)


def _sed_read(args: list[str]) -> bool:
    opts, pos = _options(args, "efl", {"--expression", "--file", "--line-length"})
    if not _known(opts, "nErsuzel", {"--quiet", "--silent", "--regexp-extended", "--expression", "--separate", "--unbuffered",
                                     "--null-data", "--posix", "--debug", "--line-length", "--sandbox", "--help", "--version"}):
        return False                                       # -i, -f script file, unknown flags
    scripts = [v for o, v in opts if o in ("-e", "--expression")] or pos[:1]
    return bool(scripts) and all(_sed_script_read(s) for s in scripts)


PERL_DANGER_RE = re.compile(r"\b(?:unlink|rename|rmdir|mkdir|chmod|chown|chroot|symlink|link|truncate|utime|kill|system|exec|qx"
                            r"|open|sysopen|fork|eval|require|do|syscall|socket|dbmopen|tie|setpgrp|setpriority)\b|`|\$\^I")


def _perl_read(args: list[str]) -> bool:
    """perl -n/-p/-l/-a/-e only (no -i, no modules but strict/warnings); the code may not name any I/O or exec builtin."""
    opts, pos = _options(args, "eE", (), glued_only="FCMm", glued_digits="0l")
    if not _known(opts, "nplawWXsEe0lCFtTMm#", ()):          # -0777 = -0 with digits
        return False
    if any(o in ("-M", "-m") and v.split("=")[0] not in ("strict", "warnings", "utf8") for o, v in opts):
        return False
    code = [v for o, v in opts if o in ("-e", "-E")]
    return bool(code) and not any(PERL_DANGER_RE.search(c) for c in code)


def _awk_read(args: list[str]) -> bool:
    opts, _ = _options(args, "Fv", {"--field-separator", "--assign"})
    return _known(opts, "FvbcPSM", {"--field-separator", "--assign", "--posix", "--traditional", "--characters-as-bytes",
                                    "--sandbox", "--bignum", "--re-interval", "--lint", "--version", "--help",
                                    "--use-lc-numeric", "--non-decimal-data"})   # no -f/-E/-i/-l/-o/-p/-d


def _code_flags_read(name: str, args: list[str]) -> bool:
    """Interpreters with inline code: only flags that cannot preload code or write files."""
    if PY_RE.match(name):
        opts, _ = _options(args, "cXW", ())
        return _known(opts, "IEsSBuOqbRVhcXWP", ())
    if name == "php":
        opts, _ = _options(args, "r", ())
        return _known(opts, "rnqH", ())                    # no -d auto_prepend_file=…, no -c ini
    if name in ("node", "nodejs"):
        opts, _ = _options(args, "ep", {"--eval", "--print"})
        return _known(opts, "ep", {"--eval", "--print", "--no-warnings", "--no-deprecation", "--input-type", "--version", "--help"})
    if name == "ruby":
        opts, _ = _options(args, "e", (), glued_only="F", glued_digits="0l")
        return _known(opts, "ewnplaFW0", ())                # no -r lib, -I, -i, -x
    if name == "perl":
        return _perl_read(args)
    if name in AWKS:
        return _awk_read(args)
    return True


TAR_LONG = set("""--list --create --file --gzip --gunzip --ungzip --bzip2 --xz --zstd --lzma --lzip --lzop --auto-compress
--exclude --exclude-from --exclude-vcs --exclude-caches --exclude-backups --wildcards --no-wildcards --wildcards-match-slash
--anchored --no-anchored --ignore-case --verbose --directory --null --no-null --files-from --numeric-owner --full-time --utc
--totals --warning --one-file-system --ignore-failed-read --sort --owner --group --mtime --format --posix
--show-transformed-names --transform --xform --occurrence --dereference --hard-dereference --block-number --recursion
--no-recursion --seek --record-size --blocking-factor --acls --xattrs --selinux --no-acls --no-xattrs --absolute-names
--checkpoint""".split())                    # no --to-command, --checkpoint-action, -I/--use-compress-program, -F, -g, --remove-files


def _tar_read(args: list[str]) -> bool:
    """v6: list (-t) or create to stdout (-cf -) with known options only."""
    bundle = args[0] if args and re.fullmatch(r"[A-Za-z]+", args[0]) else ""
    rest = (["-" + bundle] + args[1:]) if bundle else args
    opts, _ = _options(rest, "fCTXb", {"--file", "--directory", "--files-from", "--exclude-from", "--exclude", "--transform",
                                       "--xform", "--owner", "--group", "--mtime", "--format", "--sort", "--occurrence",
                                       "--record-size", "--blocking-factor", "--warning", "--checkpoint"})
    if not _known(opts, "tcvfzjJaCTXphSnb", TAR_LONG):
        return False
    names = {o for o, _ in opts}
    files = [v for o, v in opts if o in ("-f", "--file")]
    if names & {"-t", "--list"}:
        return not names & {"-c", "--create"}
    return bool(names & {"-c", "--create"}) and files == ["-"]


def _less_read(args: list[str]) -> bool:
    """No +!cmd / +|cmd (only +F, +G, +g, +N, +/pattern), no -o/-O log file, no -k lesskey."""
    if any(a.startswith("+") and not re.fullmatch(r"\+(?:[FGg]|\d+|/[^!|]*)", a) for a in args):
        return False
    opts, _ = _options([a for a in args if not a.startswith("+")], "xzhbyjpPt", ())
    return _known(opts, "RSNnXFiIMmEeKQqrfwWsAcCdDLBuUaGgJ~xzhbyjpPt#", {
        "--RAW-CONTROL-CHARS", "--raw-control-chars", "--chop-long-lines", "--LINE-NUMBERS", "--line-numbers",
        "--quit-if-one-screen", "--no-init", "--ignore-case", "--IGNORE-CASE", "--follow-name", "--squeeze-blank-lines",
        "--tabs", "--quiet", "--silent", "--QUIT-AT-EOF", "--quit-at-eof", "--long-prompt", "--version", "--help",
        "--mouse", "--no-lessopen", "--header", "--incsearch", "--use-color", "--no-keypad"})


def _ss_read(args: list[str]) -> bool:
    opts, _ = _options(args, "fANF", {"--family", "--query", "--socket", "--net", "--filter"})
    return _known(opts, "tuwxlanprmoeisSdHE046bOMNAfFhzZT", {
        "--tcp", "--udp", "--raw", "--unix", "--packet", "--dccp", "--sctp", "--vsock", "--tipc", "--xdp", "--mptcp",
        "--listening", "--all", "--numeric", "--resolve", "--processes", "--threads", "--extended", "--memory", "--options",
        "--info", "--summary", "--no-header", "--oneline", "--ipv4", "--ipv6", "--family", "--query", "--socket", "--net",
        "--filter", "--context", "--contexts", "--cgroup", "--tos", "--bpf", "--events", "--help", "--version"})   # no -K, -D


CURL_LONG = set("""--silent --show-error --fail --fail-with-body --location --head --include --verbose --insecure --get
--compressed --http1.0 --http1.1 --http2 --http2-prior-knowledge --http3 --ipv4 --ipv6 --no-progress-meter --progress-bar
--header --user-agent --referer --user --proxy --noproxy --range --cookie --cert --key --cacert --capath --cert-type
--key-type --pinnedpubkey --resolve --connect-to --interface --unix-socket --abstract-unix-socket --max-time
--connect-timeout --retry --retry-delay --retry-max-time --retry-connrefused --max-filesize --limit-rate --keepalive-time
--no-keepalive --tcp-nodelay --tlsv1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3 --tls-max --ciphers --url --path-as-is --globoff
--write-out --output --request --dump-header --netrc --netrc-optional --disable --no-buffer --location-trusted
--max-redirs --proto --proto-redir --ssl-no-revoke --no-alpn --no-npn --sslv2 --sslv3 --digest --basic --ntlm
--negotiate --anyauth --raw --styled-output --no-styled-output --create-dirs --remote-time --remote-name --remote-header-name
--remote-name-all""".split()) - {"--create-dirs", "--remote-time", "--remote-name", "--remote-header-name", "--remote-name-all"}
CURL_VALUED_LONG = {"--header", "--user-agent", "--referer", "--user", "--proxy", "--noproxy", "--range", "--cookie", "--cert",
                    "--key", "--cacert", "--capath", "--cert-type", "--key-type", "--pinnedpubkey", "--resolve", "--connect-to",
                    "--interface", "--unix-socket", "--abstract-unix-socket", "--max-time", "--connect-timeout", "--retry",
                    "--retry-delay", "--retry-max-time", "--max-filesize", "--limit-rate", "--keepalive-time", "--tls-max",
                    "--ciphers", "--url", "--write-out", "--output", "--request", "--dump-header", "--max-redirs", "--proto",
                    "--proto-redir"}


def _curl_read(args: list[str]) -> bool:
    """v6: curl options are an allowlist (no -K config, -d/-F/-T data, -c cookie jar, -O); -o/-D only to /dev/null or -,
    -X only GET/HEAD/OPTIONS."""
    opts, _ = _options(args, "HmwAeuxrbEoDXy", CURL_VALUED_LONG)
    if not _known(opts, "sSfLIvkiG46Nq#gHmwAeuxrbEoDX", CURL_LONG):
        return False
    for name, value in opts:
        if name in ("-o", "--output", "-D", "--dump-header") and value not in ("/dev/null", "-"):
            return False
        if name in ("-X", "--request") and value.strip("'\"").upper() not in ("GET", "HEAD", "OPTIONS"):
            return False
    return True


FIND_ARG1 = set("""-name -iname -path -ipath -wholename -iwholename -regex -iregex -type -xtype -mtime -mmin -atime -amin -ctime
-cmin -newer -anewer -cnewer -size -user -group -uid -gid -perm -maxdepth -mindepth -links -inum -samefile -lname -ilname
-fstype -regextype -used -context -printf""".split())
FIND_ARG0 = set("""-print -print0 -ls -prune -quit -true -false -empty -executable -readable -writable -nouser -nogroup -xdev
-mount -depth -daystart -follow -noleaf -ignore_readdir_race -noignore_readdir_race -warn -nowarn -a -and -o -or -not -d""".split())


def _find_read(args: list[str]) -> bool:
    """v6: find expression is an allowlist (tests + print actions); -exec/-ok contents are judged by _embedded."""
    k = 0
    while k < len(args) and args[k] in ("-H", "-L", "-P") or (k < len(args) and re.fullmatch(r"-O\d", args[k])):
        k += 1
    if k < len(args) and args[k] == "-D":
        k += 2
    while k < len(args) and not args[k].startswith(("-", "(", "!", ")")):
        k += 1                                             # start paths
    while k < len(args):
        a = args[k]
        if a in ("(", ")", "!", ",", "\\(", "\\)") or a in FIND_ARG0:
            k += 1
        elif a in FIND_ARG1 or re.fullmatch(r"-newer[aBcmt][aBcmt]", a):
            k += 2
        elif a in ("-exec", "-execdir", "-ok", "-okdir"):
            k += 1
            while k < len(args) and args[k] not in (";", "\\;", "+"):
                k += 1
            k += 1
        else:
            return False                                   # -delete, -fprint*, -fls, unknown
    return True


def _export_read(args: list[str]) -> bool:
    return not any((m := re.match(r"([A-Za-z_]\w*)=", a)) and DANGEROUS_ENV_RE.match(m.group(1)) for a in args)


SYSTEMCTL_READ = {"status", "is-active", "is-enabled", "is-failed", "is-system-running", "list-units", "list-unit-files",
                  "list-timers", "list-sockets", "list-dependencies", "list-jobs", "list-machines", "list-automounts",
                  "list-paths", "show", "cat", "help", "get-default", "show-environment", ""}
VIRSH_READ = {"list", "dominfo", "domstate", "dumpxml", "domblklist", "domiflist", "domifaddr", "dommemstat", "domstats",
              "nodeinfo", "nodememstats", "nodecpustats", "capabilities", "net-list", "net-info", "net-dumpxml",
              "net-dhcp-leases", "pool-list", "pool-info", "pool-dumpxml", "vol-list", "vol-info", "vol-dumpxml",
              "snapshot-list", "snapshot-info", "snapshot-dumpxml", "version", "uri", "hostname", "sysinfo", "vcpuinfo",
              "vcpucount", "domblkinfo", "domblkstat", "domifstat", "domjobinfo", "domhostname", "domid", "domname",
              "domuuid", "iface-list", "iface-dumpxml", "nodedev-list", "nodedev-dumpxml", "secret-list", "nwfilter-list",
              "domcontrol", "domdisplay", "vncdisplay", "emulatorpin", "iothreadinfo", "domfsinfo", "help", "freecell"}
REDIS_READ = {"get", "mget", "keys", "scan", "info", "ping", "ttl", "pttl", "type", "exists", "strlen", "hget", "hmget",
              "hgetall", "hkeys", "hvals", "hlen", "hexists", "hscan", "lrange", "llen", "lindex", "smembers", "scard",
              "sismember", "sscan", "zrange", "zrangebyscore", "zcard", "zscore", "zscan", "dbsize", "time", "role",
              "lastsave", "--scan", "--bigkeys", "--memkeys", "--stat", "--latency", "--version"}
REDIS_OPTS = ("-h", "-p", "-a", "-n", "-u", "-s", "--user", "--pass", "-r", "-i", "-d", "--cacert", "--cert", "--key")
PS_READ_VERB = r"(?:Get|Test|Select|Format(?!-Volume)|Measure|Where|Sort|Group|ConvertTo|ConvertFrom|Resolve|Compare|Find|Search|Write(?!-EventLog)|Out-(?:String|Host|Null|Default)|Join|Split|Show|Read|Trace|Wait|Use)"
PS_READ_NAME = re.compile(rf"(?i)^(?:{PS_READ_VERB}-\w+|New-(?:PSSession|CimSession|PSSessionOption|Object|TimeSpan)"
                          r"|ForEach-Object|%|\?|foreach|whoami|ipconfig|systeminfo|tasklist|ver|findstr|where|dir"
                          r"|type|ping|tracert|pathping|nslookup|getmac|nbtstat|qwinsta|quser|query|chcp|cls|\$\w+)$")
PS_CMDLET_TOKEN = re.compile(r"^(?:Set|Remove|New|Stop|Start|Restart|Clear|Add|Rename|Move|Copy|Install|Uninstall|Enable"
                             r"|Disable|Register|Unregister|Invoke|Suspend|Resume|Update|Reset|Mount|Dismount|Import|Export"
                             r"|Grant|Revoke|Block|Unblock|Initialize|Repair|Save|Publish|Unpublish|Lock|Unlock|Protect"
                             r"|Unprotect|Send|Connect|Disconnect|Format-Volume|Out-File|Write-EventLog)-[A-Za-z]+$")
OS_RELEASE = ("/etc/os-release", "/usr/lib/os-release", "/etc/lsb-release")
ALWAYS_READ = set("""cat tac head tail grep egrep fgrep zgrep zcat bzcat xzcat ls dir vdir stat wc cut tr nl column fold paste join comm
diff cmp md5sum sha1sum sha224sum sha256sum sha384sum sha512sum b2sum cksum sum base64 base32 od hexdump strings
readlink realpath basename dirname pwd id whoami groups who w last lastb lastlog users uname uptime cal df du free
vmstat iostat mpstat pidstat lscpu lsblk lsusb lspci lsmod lsof blkid findmnt ps pgrep pidof pstree top htop iotop
nproc getconf printenv locale netstat ping ping6 traceroute traceroute6 tracepath mtr dig host nslookup whois fping
echo printf true false test [ [[ : cd pushd popd set  shift sleep wait read exit return type which whereis hash
alias unalias umask ulimit shopt let break continue seq getent jq envsubst bc expr lsattr getfacl namei modinfo
lldpctl systemd-analyze systemd-cgls systemd-cgtop systemd-detect-virt atq pveversion lvs vgs pvs lvdisplay vgdisplay
pvdisplay xargs tty ssh-keyscan lshw dmidecode lsns lslocks lsscsi lsipc getcap sestatus getenforce aa-status ausearch
aureport showmount smbstatus testparm mailq named-checkconf virt-what virt-top iftop nload bmon getopts""".split())   # v6: no program with an exec/write flag
READ = {
    "sort": lambda a: not _has(a, "-o", "--output"), "uniq": lambda a: len(_pos(a, ("-f", "-s", "-w"))) <= 1,
    "tee": lambda a: all(p in ("/dev/null", "/dev/stderr", "/dev/stdout") for p in _pos(a)),
    "xxd": lambda a: len(_pos(a, ("-c", "-g", "-l", "-o", "-s", "-n"))) <= 1, "tree": lambda a: not _has(a, "-o"),
    "hostname": lambda a: not _pos(a) and not _has(a, "-F", "-b", "--file", "--boot"),
    "date": lambda a: not _has(a, "-s", "--set") and all(p.startswith("+") for p in _pos(a, ("-d", "--date", "-r", "--reference", "-I"))),
    "mount": lambda a: not _pos(a, ("-t", "-O")), "kill": lambda a: a[:1] in (["-l"], ["-L"], ["-0"]),
    "sysctl": lambda a: not _has(a, "-w", "-p", "--write", "--load", "--system") and not any("=" in p for p in _pos(a)),
    "nmap": lambda a: not any(x.startswith(("-o", "--script", "-sC", "-A")) for x in a), "tcpdump": lambda a: not _has(a, "-w"),
    "openssl": lambda a: not _has(a, "-out", "-keyout") and "-out" not in a and "-keyout" not in a,
    "ssh-keygen": lambda a: _has(a, "-l", "-F", "-y", "-L", "-Q", "-E"), "fuser": lambda a: not _has(a, "-k"),
    "nc": lambda a: _has(a, "-z"), "ncat": lambda a: _has(a, "-z"), "netcat": lambda a: _has(a, "-z"),
    "curl": _curl_read, "wget": lambda a: not WGET_WRITE_RE.search(" ".join(["wget", *a])),
    "unzip": lambda a: _has(a, "-l", "-t", "-v", "-p", "-Z", "-z"), "tar": _tar_read,
    "sed": _sed_read, "perl": _perl_read, "less": _less_read, "more": _less_read, "zless": _less_read, "ss": _ss_read,
    "export": _export_read, "local": _export_read, "declare": _export_read, "typeset": _export_read, "readonly": _export_read,
    "rg": lambda a: not any(x.startswith("--pre") for x in a),
    "file": lambda a: _known(_options(a, "eFPm", {"--exclude", "--separator", "--parameter", "--magic-file"})[0],
                             "bciLhzZkrsNnp0EeFPm", {"--brief", "--mime", "--mime-type", "--mime-encoding", "--dereference",
                                                    "--no-dereference", "--uncompress", "--uncompress-noreport", "--keep-going",
                                                    "--raw", "--special-files", "--no-pad", "--print0", "--extension",
                                                    "--apple", "--exclude", "--separator", "--parameter", "--magic-file",
                                                    "--preserve-date", "--no-buffer", "--version", "--help"}),   # v7: no -f, -C
    "unset": lambda a: not any(DANGEROUS_ENV_RE.match(x) for x in a if not x.startswith("-")),   # v7: unset PATH
    "sar": lambda a: not _has(a, "-o"), "dstat": lambda a: not any(x.startswith("--output") for x in a),
    "postqueue": lambda a: a in (["-p"], ["-j"]), "nfsstat": lambda a: not _has(a, "-z", "--zero"),
    "arping": lambda a: not _has(a, "-U", "-A"), "sensors": lambda a: not _has(a, "-s", "--set"),
    "mii-tool": lambda a: not _has(a, "-F", "-r", "-R", "-A", "--force", "--restart", "--reset", "--advertise"),
    "crontab": lambda a: a == ["-l"] or (len(a) == 3 and a[0] == "-u" and a[2] == "-l") or (len(a) == 3 and a[0] == "-l"),
    "journalctl": lambda a: not any(re.match(r"--(?:rotate|vacuum|flush|sync|relinquish|smart-relinquish|setup-keys|update-catalog)", x) for x in a),
    "dmesg": lambda a: not _has(a, "-c", "-C", "-D", "-E", "-n", "--clear", "--read-clear", "--console-off", "--console-on", "--console-level"),
    "systemctl": lambda a: _verb(a, ("-t", "--type", "-p", "--property", "-n", "--lines", "-o", "--output", "--state", "-H", "--host", "-M", "--machine", "--root")) in SYSTEMCTL_READ,
    "service": lambda a: a[-1:] == ["status"] or a == ["--status-all"],
    "timedatectl": lambda a: _verb(a) in ("status", "show", "list-timezones", "timesync-status", "show-timesync", ""),
    "hostnamectl": lambda a: _verb(a) in ("status", ""), "localectl": lambda a: _verb(a) in ("status", "list-locales", "list-keymaps", "list-x11-keymap-models", ""),
    "loginctl": lambda a: re.match(r"(?:list-|show-|session-status|user-status|seat-status|$)", _verb(a)) is not None,
    "busctl": lambda a: _verb(a) in ("list", "status", "tree", "introspect", "get-property", "monitor", ""),
    "networkctl": lambda a: _verb(a) in ("list", "status", "lldp", "label", ""), "resolvectl": lambda a: _verb(a) in ("status", "query", "statistics", ""),
    "ufw": lambda a: _verb(a) in ("status", "show", "version"),
    "firewall-cmd": lambda a: bool(a) and all(re.match(r"--(?:state|list|get|query|info|version|zone=|permanent$)", x) for x in a),
    "ip": _ip_read, "bridge": _ip_read,
    "tc": lambda a: not any(x in ("-b", "-batch", "-force") or x.startswith("-batch") for x in a) and (len(_pos(a)) < 2 or _pos(a)[1] in ("show", "list", "ls", "sh")),
    "iptables": lambda a: _has(a, "-L", "-S", "--list", "--list-rules") and not _has(a, "-A", "-D", "-I", "-R", "-F", "-Z", "-N", "-X", "-P", "-E", "--append", "--delete", "--insert", "--flush", "--zero", "--policy"),
    "iptables-save": lambda a: not _has(a, "-f", "--file"),
    "nft": lambda a: _verb(a, ("-f", "--file", "-I", "--includepath")) in ("list", "describe", "monitor") or (_has(a, "-c", "--check")),
    "ipset": lambda a: _verb(a) in ("list", "save", "test", "-l") or _has(a, "-L", "-S"),
    "conntrack": lambda a: _has(a, "-L", "-S", "-C", "-G", "-E", "--dump", "--stats", "--count", "--get", "--event") and not _has(a, "-D", "-F", "-I", "-U", "--delete", "--flush", "--create", "--update"),
    "arp": lambda a: not _has(a, "-d", "-s", "-f", "--delete", "--set", "--file"),
    "route": lambda a: not set(_pos(a)) & {"add", "del", "delete", "flush", "change", "replace"},
    "ifconfig": lambda a: len(_pos(a)) <= 1, "ethtool": _ethtool_read, "brctl": lambda a: _verb(a).startswith("show") or not a,
    "ovs-vsctl": lambda a: re.match(r"(?:list|show|get|find|br-exists|br-to-|port-to-br|iface-to-br|$)", _verb(a, ("--db", "-t", "--timeout"))) is not None,
    "ovs-ofctl": lambda a: re.match(r"(?:dump-|show|queue-stats|snoop|monitor)", _verb(a)) is not None,
    "nmcli": lambda a: not set(x.lower() for x in a) & {"up", "down", "add", "delete", "del", "modify", "mod", "edit", "reload", "connect", "disconnect", "set", "load", "import", "export", "clone", "on", "off", "migrate"} and not (("hostname" in a) and a[-1] != "hostname"),
    "virsh": lambda a: _verb(a, ("-c", "--connect", "-l", "--log", "-k", "--keepalive-interval", "-K", "--keepalive-count")) in VIRSH_READ,
    "vtysh": _vtysh_read,
    "birdc": lambda a: _verb(a, ("-s",)) in ("show", "sh"), "birdc6": lambda a: _verb(a, ("-s",)) in ("show", "sh"), "birdcl": lambda a: _verb(a, ("-s",)) in ("show", "sh"),
    "accel-cmd": lambda a: _verb(a, ("-H", "-p", "-P", "-t")) in ("show", "help"),
    "mysqladmin": lambda a: _verb(a, ("-u", "-h", "-P", "-p", "-S", "--socket", "--user", "--host", "--port")) in ("status", "variables", "processlist", "ping", "version", "extended-status"),
    "redis-cli": lambda a: (_pos(a, REDIS_OPTS)[:1] or [""])[0].lower() in REDIS_READ or (not _pos(a, REDIS_OPTS) and _has(a, "--scan", "--bigkeys", "--memkeys", "--stat", "--latency", "--version")) or (_pos(a, REDIS_OPTS)[:2] == ["CONFIG", "GET"] or [x.lower() for x in _pos(a, REDIS_OPTS)[:2]] in (["config", "get"], ["client", "list"], ["slowlog", "get"], ["memory", "usage"])),
    "docker": _docker_read, "podman": _docker_read, "docker-compose": lambda a: _docker_read(["compose", *a]),
    "kubectl": lambda a: _verb(a, ("-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server")) in ("get", "describe", "logs", "top", "explain", "version", "cluster-info", "api-resources", "api-versions", "events", "diff", "auth") or " ".join(_pos(a, ("-n", "--namespace", "--context", "--kubeconfig"))[:2]) in ("config view", "config get-contexts", "config current-context"),
    "helm": lambda a: _verb(a, ("-n", "--namespace", "--kube-context")) in ("list", "ls", "status", "get", "history", "show", "search", "version", "env", "template", "lint"),
    "git": _git_read,
    "find": _find_read, "awk": lambda a: False,             # find -exec / awk code: _embedded; awk -f = opaque
    "zfs": lambda a: _verb(a) in ("list", "get", "holds", "diff", "version", "userspace", "groupspace"),
    "zpool": lambda a: _verb(a) in ("list", "status", "iostat", "get", "history", "version", "events"),
    "mdadm": lambda a: _has(a, "--detail", "-D", "--examine", "-E", "--query", "-Q") and not _has(a, "--create", "--grow", "--add", "--remove", "--fail", "--stop", "--zero-superblock", "--assemble", "--run", "--readonly", "--readwrite", "-C", "-G", "-a", "-r", "-f", "-S", "-A"),
    "parted": lambda a: (_has(a, "-l", "--list") or "print" in a) and not set(a) & {"rm", "mkpart", "mklabel", "mktable", "resizepart", "set", "toggle", "name", "rescue", "mkfs", "cp", "move", "resize", "disk_set", "disk_toggle"},
    "fdisk": lambda a: _has(a, "-l", "--list"), "sfdisk": lambda a: _has(a, "-l", "-d", "-s", "--list", "--dump", "--show-size", "-J", "--json"),
    "smartctl": lambda a: not _has(a, "-s", "-t", "-X", "-o", "-S", "--set", "--test", "--abort", "--offlineauto", "--saveauto"),
    "hwclock": lambda a: all(x in ("-r", "--show", "--get", "--verbose", "-D", "--debug", "--test", "--utc", "--localtime", "-u") for x in a),
    "ipmitool": lambda a: not set(x.lower() for x in a) & {"set", "on", "off", "cycle", "reset", "clear", "delete", "add", "soft", "bootdev", "raw", "diag", "activate", "deactivate", "enable", "disable", "write", "edit"},
    "nginx": lambda a: _has(a, "-t", "-T", "-v", "-V") and not _has(a, "-s"),
    "apachectl": lambda a: bool(a) and all(x in ("-t", "-S", "-M", "-v", "-V", "-l", "-L", "-T", "-D", "DUMP_VHOSTS", "DUMP_MODULES", "DUMP_RUN_CFG", "configtest", "status", "fullstatus") for x in a),
    "php": lambda a: (_pos(a)[:1] == ["artisan"] or bool(re.search(r"/artisan$", (_pos(a) or [""])[0]))) and re.match(r"(?:list|help|about|env|inspire|route:list|migrate:status|schedule:list|queue:monitor|db:show|db:table|model:show|event:list|channel:list|-V|--version)$", (_pos(a)[1:2] or a[-1:] or ["?"])[0]) is not None or (bool(a) and all(x in ("-v", "--version", "-m", "-i", "--ini", "-n") for x in a)),
    "composer": lambda a: _verb(a) in ("show", "info", "diagnose", "outdated", "licenses", "check-platform-reqs", "validate", "depends", "why", "why-not", "prohibits", "fund", "search", "list", "help", "about", "status", "config") and not (_verb(a) == "config" and len(_pos(a)) > 2),
    "npm": lambda a: _verb(a) in ("ls", "list", "view", "info", "outdated", "help", "doctor", "audit", "explain", "why", "root", "prefix", "bin") or a in (["-v"], ["--version"]) or _pos(a)[:2] == ["config", "get"],
    "pip": lambda a: _verb(a) in ("list", "show", "freeze", "check", "debug", "help", "index", "inspect") or a in (["-V"], ["--version"]),
    "apt": lambda a: _verb(a) in ("list", "show", "search", "policy", "depends", "rdepends", "showsrc", "changelog", "help"),
    "apt-cache": lambda a: _verb(a) not in ("gencaches",), "dpkg-query": lambda a: True,
    "dpkg": lambda a: _has(a, "-l", "-L", "-s", "-S", "-p", "--list", "--listfiles", "--status", "--search", "--print-avail", "--get-selections", "--print-architecture", "--audit", "-C", "--compare-versions") and not _has(a, "-i", "-r", "-P", "--install", "--remove", "--purge", "--configure", "--set-selections", "--unpack"),
    "rpm": lambda a: (_has(a, "-q", "-V", "--query", "--verify", "--showrc") or a == ["--version"]) and not _has(a, "-i", "-U", "-F", "-e", "--install", "--upgrade", "--freshen", "--erase", "--import", "--rebuilddb", "--setperms", "--setugids", "--restore"),
    "yum": lambda a: _verb(a) in ("list", "info", "search", "repolist", "provides", "whatprovides", "deplist", "check-update", "history", "repoquery", "help"),
    "dnf": lambda a: _verb(a) in ("list", "info", "search", "repolist", "provides", "whatprovides", "deplist", "check-update", "history", "repoquery", "help"),
    "snap": lambda a: _verb(a) in ("list", "info", "find", "version", "services", "changes", "connections", "help"),
    "pct": lambda a: _verb(a) in ("list", "status", "config", "pending", "listsnapshot", "df", "cpusets", "help"),
    "qm": lambda a: _verb(a) in ("list", "status", "config", "pending", "listsnapshot", "showcmd", "help") or (_pos(a)[:2] == ["guest", "exec-status"]) or (_pos(a)[:2] == ["guest", "cmd"] and re.match(r"(?:ping|info|get-\S+|network-get-interfaces)$", (_pos(a)[3:4] or ["?"])[0]) is not None),
    "pvesh": lambda a: _verb(a) in ("get", "ls", "usage", "help"), "pvesm": lambda a: _verb(a) in ("status", "list", "path", "scan", "help"),
    "ha-manager": lambda a: _verb(a) in ("status", "config", "groupconfig", "help"), "pveam": lambda a: _verb(a) in ("list", "available", "help"),
    "tmux": lambda a: _verb(a, ("-L", "-S", "-f")) in ("ls", "list-sessions", "list-windows", "lsw", "list-panes", "lsp", "has-session", "has", "capture-pane", "capturep", "show-options", "show", "show-window-options", "showw", "display-message", "display", "list-clients", "lsc", "info", "list-commands", "list-keys", "lsk", "-v", "-V"),
    "screen": lambda a: _has(a, "-ls", "-list") or a in (["-ls"], ["-list"], ["--version"], ["-v"]),
    "logrotate": lambda a: _has(a, "-d", "--debug"), "make": lambda a: _has(a, "-n", "-q", "-p", "--dry-run", "--just-print", "--recon", "--question", "--print-data-base"),
    "gzip": lambda a: _has(a, "-c", "-l", "-t", "--stdout", "--to-stdout", "--list", "--test") or not _pos(a),
    "logger": lambda a: False, "source": lambda a: bool(_pos(a)) and _pos(a)[0] in OS_RELEASE, ".": lambda a: bool(_pos(a)) and _pos(a)[0] in OS_RELEASE,
    "command": lambda a: _has(a, "-v", "-V"), "swapon": lambda a: all(x in ("--show", "-s", "--summary", "--noheadings", "--bytes", "--raw") or x.startswith("--show=") for x in a) and bool(a),
    "exportfs": lambda a: all(x in ("-v", "-s") for x in a), "chronyc": lambda a: _verb(a, ("-h", "-p")) in ("sources", "tracking", "sourcestats", "activity", "ntpdata", "clients", "serverstats", "-n", ""),
    "ntpq": lambda a: True, "auditctl": lambda a: _has(a, "-l", "-s") and not _has(a, "-a", "-A", "-d", "-D", "-w", "-W", "-e", "-f", "-r", "-b", "-R"),
    "postconf": lambda a: not _has(a, "-e", "-X", "-#", "-M", "-P"), "named-checkzone": lambda a: not _has(a, "-o"),
    "haproxy": lambda a: _has(a, "-c", "-v", "-vv"), "visudo": lambda a: _has(a, "-c", "--check"), "sshd": lambda a: _has(a, "-t", "-T", "-V"),
    "rndc": lambda a: _verb(a, ("-s", "-p", "-k", "-c")) in ("status", "zonestatus", "tsig-list"),
    "faillock": lambda a: not _has(a, "--reset"), "chage": lambda a: _has(a, "-l", "--list"), "passwd": lambda a: _has(a, "-S", "--status"),
    "codex": lambda a: a in (["--version"], ["-V"]) or _pos(a)[:2] in (["mcp", "get"], ["mcp", "list"]), "claude": lambda a: a in (["--version"], ["-v"]),
    "net": lambda a: _verb(a) in ("view", "statistics", "config") or (len(a) == 1 and _verb(a) in ("user", "localgroup", "share", "session", "use", "accounts", "start")),
    "sc": lambda a: _verb([x for x in a if not x.startswith("\\\\")]) in ("query", "queryex", "qc", "qdescription", "qfailure", "qtriggerinfo", "getdisplayname", "getkeyname", "enumdepend", "sdshow", "showsid"),
    "reg": lambda a: _verb(a) in ("query", "compare"), "schtasks": lambda a: any(x.lower() == "/query" for x in a),
    "wmic": lambda a: bool(set(x.lower() for x in a) & {"get", "list"}) and not set(x.lower() for x in a) & {"call", "delete", "set", "create"},
    "iptables-legacy": None, "ip6tables": None, "ip6tables-legacy": None, "iptables-nft": None, "ip6tables-nft": None,
    "ip6tables-save": None, "apache2ctl": None, "httpd": None, "pip3": None, "unpigz": None, "gunzip": None, "xz": None,
    "unxz": None, "bzip2": None, "bunzip2": None, "zstd": None, "unzstd": None, "lz4": None, "pigz": None,
}
for _alias, _base in (("iptables-legacy", "iptables"), ("ip6tables", "iptables"), ("ip6tables-legacy", "iptables"),
                      ("iptables-nft", "iptables"), ("ip6tables-nft", "iptables"), ("ip6tables-save", "iptables-save"),
                      ("apache2ctl", "apachectl"), ("httpd", "apachectl"), ("pip3", "pip")):
    READ[_alias] = READ[_base]
for _alias in ("unpigz", "gunzip", "xz", "unxz", "bzip2", "bunzip2", "zstd", "unzstd", "lz4", "pigz"):
    READ[_alias] = READ["gzip"]
for _sql in SQL_CLIENTS:
    READ[_sql] = (lambda n: lambda a: _sql_client_read(n, a))(_sql)


def _wrapped(name: str, args: list[str]) -> list[str] | None:
    """v5: the command a wrapper runs (runuser/flock/chroot/nsenter/unshare/systemd-run/chrt/taskset/setpriv,
    tmux new, screen -dm, parallel, ip netns exec, docker exec, trap). [] = runs a shell (opaque); None = not a wrapper."""
    spec = {"runuser": ({"-u", "-g", "-G", "-l", "-s", "-w", "--user", "--group", "--supp-group", "--shell"}, 0),
            "flock": ({"-w", "-E", "--timeout", "--conflict-exit-code"}, 1), "chroot": ({"--userspec", "--groups"}, 1),
            "nsenter": ({"-t", "--target", "-S", "--setuid", "-G", "--setgid"}, 0), "unshare": (set(), 0),
            "systemd-run": ({"-p", "--property", "-u", "--unit", "--description", "--slice", "-E", "--setenv", "--uid",
                             "--gid", "-M", "--machine", "-H", "--host", "--on-calendar", "--on-active", "--on-boot",
                             "--on-startup", "--on-unit-active", "--on-unit-inactive", "--timer-property",
                             "--working-directory", "--nice", "--service-type"}, 0),
            "setpriv": ({"--reuid", "--regid", "--groups"}, 0),
            "numactl": ({"-C", "-N", "-m", "-i", "-p"}, 0)}
    if name in spec:
        valued, npos = spec[name]
        k = 0
        while k < len(args) and args[k].startswith("-") and args[k] != "--":
            if args[k] in ("-c", "--command") and name in ("flock", "runuser"):
                return [args[k + 1]] if k + 1 < len(args) else []
            k += 2 if args[k] in valued else 1
        k += k < len(args) and args[k] == "--"
        k += npos
        if k < len(args) and args[k] in ("-c", "--command") and name == "flock":
            return [args[k + 1]] if k + 1 < len(args) else []
        return [_rejoin(args[k:])] if args[k:] else []
    if name == "tmux":
        pos = _pos(args, ("-L", "-S", "-f"))
        verb = pos[0] if pos else ""
        if verb in ("new", "new-session", "new-window", "neww", "split-window", "splitw", "respawn-pane", "respawnp",
                    "respawn-window", "respawnw"):
            rest = args[args.index(verb) + 1:]
            cmd = _pos(rest, ("-s", "-n", "-c", "-t", "-x", "-y", "-e", "-F", "-l", "-f"))
            return [_rejoin(cmd)] if cmd else []
        return [] if verb in ("send-keys", "send", "run-shell", "run", "pipe-pane", "pipep", "source-file", "source") else None
    if name == "screen" and any(re.fullmatch(r"-[A-Za-z]*m[A-Za-z]*", a) for a in args):
        if _has(args, "-X"):
            return []
        k = 0
        while k < len(args) and args[k].startswith("-"):    # -dmS name: a bundle ending in S takes the name
            k += 2 if args[k] in ("-c", "-t", "-p", "-Logfile", "-h", "-e") or re.fullmatch(r"-[A-Za-z]*S", args[k]) else 1
        return [_rejoin(args[k:])] if args[k:] else []
    if name == "parallel":
        k = 0
        sep = ":" * 3                                         # GNU parallel argument separator; four colons = file
        while k < len(args) and args[k].startswith("-") and args[k] not in (sep, sep + ":"):
            k += 2 if args[k] in ("-j", "--jobs", "-a", "--arg-file", "-d", "--delimiter", "-I", "--colsep", "--joblog",
                                  "--results", "--tmpdir", "--timeout", "-n", "-N", "-S", "--sshlogin") else 1
        end = next((m for m in range(k, len(args)) if args[m].startswith(sep)), len(args))
        return [_rejoin(args[k:end])] if args[k:end] else [a for a in args[end + 1:] if not a.startswith(sep)] or []
    if name == "ip" and _pos(args, ("-n", "-netns"))[:2] == ["netns", "exec"]:
        pos = _pos(args, ("-n", "-netns"))
        return [_rejoin(pos[3:])] if pos[3:] else []
    if name in ("docker", "podman") and args[:1] == ["exec"]:
        pos = _pos(args[1:], ("-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys"))
        return [_rejoin(pos[1:])] if pos[1:] else []
    if name == "trap" and args and not args[0].startswith("-"):
        return [args[0]]
    return None


def _code_is_read(label: str, code_snippets: list[str], direct: str, depth: int) -> str | None:
    if direct:
        return f"{label}:{direct}"
    for snippet in code_snippets:
        reason = remote_is_mutating(snippet, depth + 1)
        if reason:
            return f"{label}:{reason}"
    return None


def _deny_reason(words: list[str]) -> str:
    """A precise name for a change (old denylist), else unlisted:<program>."""
    line = " ".join(words)
    first = _prog_name(words[0])
    if first in FIRST_WORD or first.startswith("mkfs"):
        return f"verb:{first}"
    for rx in PATTERN_RE:
        if rx.search(line):
            return f"pattern:{first}"
    return f"unlisted:{first}"


def _command_reason(words: list[str], depth: int) -> str | None:
    """None when this simple remote command is a known read; otherwise the reason it is (or may be) a change."""
    if words and words[0] == "case":
        words = words[words.index("in") + 1:] if "in" in words else []
    while words and re.fullmatch(r"\(?[^()\s]*\)", words[0]) and words[0] not in COMPOUND_END:
        words = words[1:]                                          # case pattern a) / (a|b)
    words = [re.sub(r"^\((?!\()", "", w) if n == 0 else w for n, w in enumerate(words)]
    words = [w[:-1] if w.endswith(")") and w.count("(") < w.count(")") else w for w in words]
    words = [w for w in words if w]
    env = _env_reason(words) or _sched_reason(words)               # v6: GIT_PAGER=…, env -S; v7: ionice -p, chrt -f
    if env:
        return env
    words = _strip_prefix(words)
    clean, k = [], 0
    while k < len(words):                                          # redirections are judged by REDIRECT_RE
        if words[k][:1] in "<>" or words[k] in ("&>", "&>>"):
            if clean and clean[-1].isdigit() and k > 0 and words[k - 1] == clean[-1]:
                clean.pop()                                        # v6: the fd of 2>&1 / 2>/dev/null
            k += 2 if words[k] in ("&>", "&>>") or not words[k].endswith("&") or (
                k + 1 < len(words) and re.fullmatch(r"\d+|-", words[k + 1])) else 1
            continue
        clean.append(words[k])
        k += 1
    words = clean
    if not words or words[0] in COMPOUND_END or words[0] in ("for", "select", "function", "in", "{", "}", "(", ")"):
        return None
    name, args = _prog_name(words[0]), words[1:]
    if words[0].startswith("$") or "$" in name:
        return f"dynamic-command:{words[0]}"
    if _stdin_interpreter(words) and name in ("at", "batch"):
        return f"scheduled-job:{name}"
    wrapped = _wrapped(name, args)
    wrapped = _sched_wrapped(name, args) if wrapped is None else wrapped   # v7: chrt/taskset
    if wrapped is not None:
        return _code_is_read(f"{name}-wrapped", wrapped, "" if wrapped else "opaque-shell", depth)
    label, snippets, direct = _embedded(words)
    if label and label not in ("watch", "xargs") or direct:
        if label in ("python-c", "php-r", "node-e", "ruby-e", "perl-e") and not direct:
            extra = PY_EXTRA_RE.search(" ".join(args)) if label == "python-c" else None
            if extra:
                return f"{label}:{extra.group(0).strip()}"
        reason = _code_is_read(label or name, snippets, direct, depth)
        if reason:
            return reason
        if not _code_flags_read(name, args) or (name == "find" and not _find_read(args)):
            return f"flags:{name}"                                 # v6: perl -i, awk -f, python -m…, find -fprint
        return None
    if label in ("watch", "xargs"):
        return _code_is_read(label, snippets, "", depth) if snippets and snippets[0] else None
    if name in ALWAYS_READ or PS_READ_NAME.match(words[0]):
        return None
    if args in (["--version"], ["--help"], ["-V"]) and name not in ("rm",):
        return None
    rule = READ.get(name)
    if rule and rule(args):
        return None
    if PY_RE.match(name) and (args in (["-V"], ["--version"]) or _pos(args)[:1] == [] and args[:2] == ["-m", "json.tool"]
                              or args[:2] == ["-m", "pip"] and READ["pip"](args[2:])):
        return None
    return _deny_reason(words)


def remote_is_mutating(remote: str, _depth: int = 0) -> str | None:
    """Return the reason when the command that runs on the remote host changes it (v5: or is not a known read)."""
    if _depth > 4:
        return "nesting-too-deep"
    remote = _strip_heredocs(remote)               # heredoc bodies are data ("< __heredoc__" still feeds stdin)
    snippets, remote = _scan_substitutions(remote)  # $(...), `...`, <(...), >(...): judged on their own,
    for snippet in snippets:                       # then masked so that F=$(ls /x) stays one word
        reason = remote_is_mutating(snippet, _depth + 1)
        if reason:
            return f"subst:{reason}"
    if CALL_GATE_RE.search(remote):
        if OPTION_COMMAND_RE.search(remote):
            return "ssh-option-command-on-this-host"   # v7: ProxyCommand/LocalCommand of a nested ssh run HERE
        remote = _drop_calls(remote)               # nested ssh calls are judged for their own host
    # a shell/interpreter/SQL client/at fed by a pipe, < file or heredoc runs code the guard cannot see
    for fed, words in _pipeline(remote):
        words = _strip_prefix(words)
        if fed and words and _stdin_interpreter(words):
            return f"stdin-script:{_prog_name(words[0])}"
    if REDIRECT_RE.search(re.sub(r"'[^']*'|\"[^\"]*\"", "", remote)):
        return "redirect-to-file"
    cmdlet = next((t for t in _tokens(remote) if PS_CMDLET_TOKEN.match(t.strip("{}();"))), None)
    if cmdlet:
        return f"ps-cmdlet:{cmdlet.strip('{}();')}"
    for words in _segments(remote):
        reason = _command_reason(words, _depth)
        if reason:
            return reason
    return None


def _command_position(tokens: list[str], i: int) -> bool:
    """True when tokens[i] is the command word: first after a separator once PREFIXES (incl. runners) are skipped."""
    if re.match(r"^(?:[A-Za-z_]\w*=)?(?:\$\(|\(|`)", tokens[i]):
        return True                                # $(ssh ...), `ssh ...`, x=$(ssh ...)
    k = i
    while k > 0 and tokens[k - 1] not in SEPARATORS and not tokens[k - 1].endswith(("(", "`")):
        k -= 1
    return k + _prefix_len(tokens[k:i + 1], runners=True) == i


def _ps_block_read(body: str) -> bool:
    """A PowerShell block is a read when every statement/pipeline element starts with a read cmdlet and no
    changing cmdlet appears anywhere inside (ForEach-Object { Stop-Service $_ })."""
    words = [w for w in re.split(r"[\s{}()]+", body) if w]
    elements = [e.strip().lstrip("({").split() for e in re.split(r"[;|\n]", body)]
    return all(PS_READ_NAME.match(e[0]) for e in elements if e) and not any(PS_CMDLET_TOKEN.match(w) for w in words)


def _ps_remote_calls(command: str, hosts: dict[str, str], depth: int = 0) -> list[dict]:
    """PowerShell remoting (Invoke-Command, Enter-PSSession; v5: any cmdlet with -ComputerName/-CimSession,
    New-PSDrive to a UNC root), writes to UNC paths, psexec/winrs/sc/reg/schtasks/shutdown/wmic against a host,
    Start-Process ssh -ArgumentList."""
    calls = []
    for match in PS_REMOTING_RE.finditer(command):
        rest = command[match.end():]
        target = re.search(r"(?i)\s-(?:computername|cn|session|hostname|vmname)\s+([^\s{;|]+)", rest[:400])
        if match.group(1).lower() in ("enter-pssession", "etsn"):
            target = target or re.search(r"^\s+([^\s-][^\s;|]*)", rest)
            if target:
                calls.append(_call(target.group(1).strip("'\""), hosts, "", "ps-session", "ps", soft=True))
            continue
        if not target:
            continue                               # local Invoke-Command
        reason, block = "ps-remoting-opaque", re.search(r"\{", rest)
        if block and not re.search(r"(?i)\s-filepath\s", rest[:block.start()]):
            depth_b, j = 0, block.start()
            while j < len(rest):
                depth_b += (rest[j] == "{") - (rest[j] == "}")
                j += 1
                if not depth_b:
                    break
            reason = None if _ps_block_read(rest[block.start() + 1:j - 1]) else "ps-remoting"
        for host in target.group(1).strip("'\"").split(","):
            calls.append(_call(host, hosts, "", reason, "ps"))
    for statement in re.split(r"[;\n]", command):  # v5: Restart-Computer -ComputerName x, Get-Service -cn x | Stop-Service
        first = (statement.split() or [""])[0]
        target = re.search(r"(?i)\s-(?:computername|cn|cimsession)\s+([^\s;|{]+)", statement)
        if target and re.fullmatch(r"[A-Za-z]+-[A-Za-z]+", first) and not PS_REMOTING_RE.search(" " + first) \
                and first.lower() not in ("new-pssession", "new-cimsession", "enter-pssession"):
            reason = None if _ps_block_read(statement) else f"ps-remote-cmdlet:{first}"
            for host in target.group(1).strip("'\"").split(","):
                calls.append(_call(host, hosts, "", reason, "ps"))
    drives = {}
    for match in re.finditer(r"(?i)\bNew-PSDrive\b([^;\n]*)", command):
        name = re.search(r"(?i)-Name\s+['\"]?(\w+)", match.group(1))
        root = re.search(r"(?i)-Root\s+['\"]?(?:\\\\|//)([\w.-]+)", match.group(1))
        if name and root:
            drives[name.group(1).lower()] = root.group(1)
    for match in PS_WRITE_RE.finditer(command):
        verb, args = match.group(1).lower(), match.group(2)
        if verb in PS_COPY:
            dest = re.search(r"(?i)-destination\s+(\S+)", args)
            words = [w for w in args.split() if not w.startswith("-") and not re.fullmatch(r"/[A-Za-z]+(?::\S*)?", w)]
            args = dest.group(1) if dest else (words[1] if len(words) > 1 else "")
        for unc in UNC_RE.finditer(args):
            calls.append(_call(unc.group(1), hosts, "", f"unc-{verb}", "unc"))
        for drive in re.findall(r"(?<![\w:])([A-Za-z]\w*):[\\/]", args):
            if drive.lower() in drives:
                calls.append(_call(drives[drive.lower()], hosts, "", f"psdrive-{verb}", "unc"))
    for rx, kind, read in (
            (r"\bp(?:s|a)exec(?:64)?(?:\.exe)?\b[^;\n|]*?(?:\\\\|//)([\w.-]+)", "psexec", None),
            (r"\bwinrs(?:\.exe)?\b[^;\n|]*?-r(?:emote)?:(?:https?://)?([\w.-]+)", "winrs", None),
            (r"\bsc(?:\.exe)?\s+(?:\\\\|//)([\w.-]+)\s+(\S+)", "sc", r"(?:query|queryex|qc|qdescription|qfailure|qtriggerinfo|getdisplayname|getkeyname|enumdepend|sdshow|showsid)$"),
            (r"\breg(?:\.exe)?\s+(\w+)\s+['\"]?(?:\\\\|//)([\w.-]+)", "reg", r"(?:query|compare|export|save)$"),
            (r"\bschtasks(?:\.exe)?\b([^;\n|]*?)/s\s+['\"]?([\w.-]+)", "schtasks", r".*?/query\b"),
            (r"\bshutdown(?:\.exe)?\b[^;\n|]*?/m\s+(?:\\\\|//)([\w.-]+)", "shutdown", None),
            (r"\bwmic(?:\.exe)?\s+/node:['\"]?([\w.,-]+)['\"]?([^;\n|]*)", "wmic", None)):
        for match in re.finditer("(?i)" + rx, command):
            groups = match.groups()
            if kind in ("sc",):
                host, verb = groups
            elif kind in ("reg", "schtasks"):
                verb, host = groups
            elif kind == "wmic":
                host, verb = groups
                verb = "get" if re.search(r"(?i)\b(?:get|list)\b", verb) and not re.search(r"(?i)\b(?:call|delete|set|create)\b", verb) else "change"
                read = r"get$"
            else:
                host, verb = groups[0], ""
            reason = None if read and re.match("(?i)" + read, verb.strip()) else f"{kind}-remote"
            for h in host.split(","):
                calls.append(_call(h, hosts, "", reason, "win"))
    for match in re.finditer(r"(?i)\bStart-Process\s+(?:-FilePath\s+)?['\"]?([^\s'\"]*?(?:ssh|plink|putty|scp|sftp)(?:\.exe)?)['\"]?"
                             r"\s+(?:-ArgumentList\s+|-Args\s+)?((?:(?:'[^']*'|\"[^\"]*\")\s*,?\s*)+)", command):
        if depth < 4:                              # v5/v10: Start-Process ssh -ArgumentList 'host','rm x'
            items = [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", match.group(2))]
            calls.extend(parse_remote_calls(f"{match.group(1)} " + " ".join(items), hosts, depth + 1))
    return calls


def _call(host_token: str, hosts: dict[str, str], remote: str, reason: str | None, kind: str, soft: bool = False) -> dict:
    return {"host_token": host_token, "host": hosts.get(host_token.lower()), "remote": remote,
            "mutating": bool(reason), "reason": reason or "", "kind": kind, "soft": soft and bool(reason)}


# ---------------------------------------------------------------------------------------------------------------
# v7 (review round 6): ssh client options and transport commands carry commands too.
# ---------------------------------------------------------------------------------------------------------------
SSH_SAFE_OPTIONS = set("""batchmode connecttimeout stricthostkeychecking userknownhostsfile globalknownhostsfile identitiesonly
identityfile identityagent certificatefile port user serveraliveinterval serveralivecountmax tcpkeepalive loglevel compression
hostkeyalgorithms pubkeyacceptedkeytypes pubkeyacceptedalgorithms hostkeyalias preferredauthentications passwordauthentication
kbdinteractiveauthentication challengeresponseauthentication gssapiauthentication pubkeyauthentication numberofpasswordprompts
controlmaster controlpath controlpersist addressfamily forwardagent forwardx11 forwardx11trusted hashknownhosts checkhostip
verifyhostkeydns updatehostkeys requesttty escapechar ipqos rekeylimit ciphers macs kexalgorithms connectionattempts
visualhostkey fingerprinthash bindaddress bindinterface canonicalizehostname exitonforwardfailure clearallforwardings
sessiontype stdinnull forkafterauthentication logverbose proxyjump permitlocalcommand nohostauthenticationforlocalhost
obscurekeystroketiming gssapidelegatecredentials gssapikeyexchange gssapitrustdns protocol addkeystoagent
streamlocalbindunlink streamlocalbindmask enablesshkeysign hostbasedauthentication hostbasedacceptedalgorithms
casignaturealgorithms requiredrsasize revokedhostkeys warnweakcrypto""".split())   # v8: + harmless keys
SSH_OPTION_COMMANDS = {"proxycommand", "localcommand", "knownhostscommand"}   # run a command on the ssh client's host
TRANSPORT_ENV = {"GIT_SSH_COMMAND", "GIT_SSH", "RSYNC_RSH", "GIT_PROXY_COMMAND", "CVS_RSH", "SVN_SSH", "BORG_RSH"}
OPTION_COMMAND_RE = re.compile(r"(?i)(?:ProxyCommand|LocalCommand|KnownHostsCommand)\s*[=\s]|-proxycmd\b")


def _ssh_option(value: str) -> tuple[str, str]:
    """-o 'Key=value' / -o 'Key value' -> (key lower-case, value)."""
    parts = re.split(r"\s*=\s*|\s+", value.strip(), maxsplit=1)
    return parts[0].lower(), (parts[1] if len(parts) > 1 else "")


def _cluster(tok: str, nxt: str | None, value_letters) -> tuple[list[tuple[str, str]], int]:
    """v8 getopt for ssh/scp/sftp/rsync: -vo X -> (-v, ''), (-o, X); -qoBatchMode=yes -> (-q), (-o, BatchMode=yes);
    -R9000:h:22 -> (-R, 9000:h:22); the value is the rest of the token or the next token. Returns (opts, tokens used)."""
    out = []
    for k in range(1, len(tok)):
        if tok[k] in value_letters:
            glued = tok[k + 1:]
            out.append(("-" + tok[k], glued or (nxt or "")))
            return out, 1 if glued or nxt is None else 2
        out.append(("-" + tok[k], ""))
    return out, 1


def _o_safe(value: str) -> bool:
    """A -o option that cannot run a command, open a tunnel or change the target."""
    key, val = _ssh_option(value)
    if key in SSH_SAFE_OPTIONS or (key == "proxycommand" and val.strip().lower() == "none"):
        return True
    if key in ("sendenv", "setenv"):               # v8: only locale/format variables (SendEnv LANG LC_*, SetEnv LANG=C)
        names = [n.split("=", 1)[0] for n in re.split(r"\s+", val.strip()) if n]
        return bool(names) and all(n in SAFE_ENV or re.fullmatch(r"LC_[A-Z_*]*|LANG\*?", n) for n in names)
    return False


# ---------------------------------------------------------------------------------------------------------------
# v9 (review round 8): a GENERIC detector for values. Any value of a variable (any name, any
# assignment form), of a config entry (any git key, GIT_CONFIG_*), or of a command-bearing option is judged as the
# command line it is: a call of ssh/scp/rsync/… inside it is found and judged for its own host; a transport variable or
# key whose value is not a plain ssh is opaque; a program that runs on the git SERVER (--upload-pack…) is opaque.
# ---------------------------------------------------------------------------------------------------------------
ASSIGN_RE = re.compile(r"(?:\$\{?env:)?([A-Za-z_]\w*)\}?\+?=(.*)", re.S | re.I)   # NAME=V, $env:NAME=V, ${env:NAME}=V
GIT_SERVER_PROGRAM_RE = re.compile(r"(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?git[- ](?:upload-pack|receive-pack|upload-archive)")
GIT_TRANSPORT_KEYS = {"core.sshcommand", "core.gitproxy"}
_EXTRA_SSH_CONFIGS = [p for p in ([os.environ["INTEGRITY_LOCK_GUARD_SSH_CONFIGS"]]
                                  if os.environ.get("INTEGRITY_LOCK_GUARD_SSH_CONFIGS")
                                  else list(_CFG.get("standard_ssh_configs") or [])) if isinstance(p, str) and p]
STD_SSH_CONFIG_RE = re.compile(r"(?i)(?:(?:^|[/\\])\.ssh[/\\]config)$|^(?:/dev/null|none)$"
                               + "".join(f"|(?:{p})" for p in _EXTRA_SSH_CONFIGS))


def _value_calls(name: str, value: str, hosts: dict[str, str], depth: int) -> list[dict]:
    """Calls hidden in a value: transport names (GIT_SSH_COMMAND, core.sshCommand…) need a plain ssh; any other value
    is parsed as a command line (git `!cmd`, `ext::cmd` included) and its remote calls are returned."""
    upper, lower = name.upper(), name.lower()
    if upper in TRANSPORT_ENV or lower in GIT_TRANSPORT_KEYS:
        return _transport_calls(name, value, hosts, depth, proxy=upper == "GIT_PROXY_COMMAND" or lower == "core.gitproxy")
    v = value.strip()
    v = v[1:] if v.startswith("!") else v
    if v.startswith("ext::"):
        v = v[5:].replace("% ", " ").replace("%%", "%")
    if depth >= 4 or not RAW_REMOTE_RE.search(v):
        return []
    return parse_remote_calls(v, hosts, depth + 1)


def _git_transport_calls(args: list[str], hosts: dict[str, str], depth: int) -> list[dict]:
    """git -c KEY=V (any key), git config KEY V, clone/fetch --config, --upload-pack/--receive-pack/--exec/-u,
    remote.*.uploadpack, ext:: URLs, rebase --exec, bisect run, submodule foreach, filter-branch filters."""
    calls, k = [], 0

    def check(key: str, value: str, where: str) -> None:
        lower = key.lower()
        if "$" in key:
            calls.append(_call(where, hosts, key, "git-config-key-unresolved", "transport"))
        elif re.fullmatch(r"remote\..+\.(?:uploadpack|receivepack)", lower):
            if not GIT_SERVER_PROGRAM_RE.fullmatch(value.strip()):
                calls.append(_call(where, hosts, value, f"git-server-program:{lower}", "transport"))
        else:
            calls.extend(_value_calls(lower if lower in GIT_TRANSPORT_KEYS else where, value, hosts, depth))

    cfg: dict[str, str] = {}
    while k < len(args) and args[k].startswith("-"):
        if args[k] == "-c" and k + 1 < len(args):
            key, _, val = args[k + 1].partition("=")
            check(key, val, f"git -c {key}")
            cfg[key.lower()] = val
            k += 2
        elif args[k].startswith("--config-env"):
            calls.append(_call("git --config-env", hosts, args[k], "git-config-env", "transport"))
            k += 1
        else:
            k += 2 if args[k] in ("-C", "--git-dir", "--work-tree", "--namespace") else 1
    verb, rest = (args[k], args[k + 1:]) if k < len(args) else ("", [])
    if verb == "config":
        pos = _pos(rest, ("--file", "-f", "--blob", "--type", "--default", "--comment"))
        if len(pos) > 1:
            check(pos[0], pos[1], f"git config {pos[0]}")
    for n, a in enumerate(rest):
        nxt = rest[n + 1] if n + 1 < len(rest) else ""
        opt, eq, val = a.partition("=")
        val = val if eq else nxt
        if a in ("-c", "--config") and nxt:
            key, _, v = nxt.partition("=")
            check(key, v, f"git {verb} --config {key}")
        elif opt == "--config" and eq:
            key, _, v = val.partition("=")
            check(key, v, f"git {verb} --config {key}")
        elif verb == "rebase" and opt in ("--exec", "-x"):
            calls.extend(_value_calls("git rebase --exec", val, hosts, depth))
        elif opt in ("--upload-pack", "--receive-pack", "--exec") or (a == "-u" and verb in ("clone", "ls-remote", "pull")):
            if not GIT_SERVER_PROGRAM_RE.fullmatch(val.strip()):       # runs on the git server: its host is not visible
                calls.append(_call(f"git {verb} {opt}", hosts, val, "git-server-program", "transport"))
        elif opt.startswith("--") and opt.endswith("-filter") and verb == "filter-branch":
            calls.extend(_value_calls(f"git filter-branch {opt}", val, hosts, depth))
        elif a.startswith("ext::"):
            calls.extend(_value_calls("git ext::", a, hosts, depth))
    if verb in ("push", "send-pack"):            # v10: git push to a known ISP host changes that host
        calls.extend(_git_push_calls(cfg, rest, hosts))
    if (verb, rest[:1]) in (("submodule", ["foreach"]), ("bisect", ["run"])):
        cmd = [a for a in rest[1:] if a not in ("--recursive", "--quiet", "-q")]
        calls.extend(_value_calls(f"git {verb} {rest[0]}", _rejoin(cmd) if len(cmd) > 1 else " ".join(cmd), hosts, depth))
    return calls


PS_ENV_SET_RE = re.compile(
    r"(?i)(?:\$\{?env:(?P<a>[A-Za-z_]\w*)\}?\s*\+?=\s*"
    r"|\b(?:Set-Item|si|New-Item|ni|Set-Content|sc|Add-Content|ac)\s+(?:-Path\s+)?['\"]?env:\\?(?P<b>[A-Za-z_]\w*)['\"]?\s+"
    r"(?:-Value\s+)?|SetEnvironmentVariable\(\s*['\"](?P<c>[A-Za-z_]\w*)['\"]\s*,\s*)"
    r"(?:'(?P<v1>[^']*)'|\"(?P<v2>[^\"]*)\"|(?P<v3>[^\s;)]+))")


def _ps_env_calls(command: str, hosts: dict[str, str], depth: int) -> list[dict]:
    """PowerShell env provider: $env:N=…, ${env:N}=…, New-Item/Set-Item/Set-Content Env:N …, SetEnvironmentVariable."""
    calls = []
    for m in PS_ENV_SET_RE.finditer(command):
        name = m.group("a") or m.group("b") or m.group("c")
        value = m.group("v1") if m.group("v1") is not None else m.group("v2") if m.group("v2") is not None else m.group("v3")
        calls.extend(_value_calls(name, value, hosts, depth))
    return calls


def _assignment_calls(tokens: list[str], hosts: dict[str, str], depth: int) -> list[dict]:
    """Every NAME=V / $env:NAME=V / --opt=V token, GIT_CONFIG_KEY_n/VALUE_n pairs, GIT_CONFIG_PARAMETERS."""
    calls, gitcfg, candidates = [], {}, []
    segs, cur = [], []
    for tok in tokens + [";"]:
        if tok in SEPARATORS:
            segs, cur = segs + [cur], []
        else:
            cur.append(tok)
    for seg in segs:                               # assignment POSITIONS only: VAR=… prefixes, export/declare/env args,
        n = _prefix_len(seg)                       # a leading $env:X=… (an ssh argument "F=…; …" is not an assignment)
        candidates += seg[:n]
        if n < len(seg) and (_prog_name(seg[n]) in ("export", "declare", "typeset", "readonly", "local", "env")
                             or re.match(r"(?i)\$\{?env:", seg[n])):
            candidates += seg[n:]
        candidates += [t for t in seg[n + 1:] if t.startswith("--") and t.partition("=")[0] in CARRIER_OPTIONS]   # v10
    for tok in candidates:
        assign = ASSIGN_RE.fullmatch(tok)
        if assign:
            name, value = assign.groups()
            pair = re.fullmatch(r"GIT_CONFIG_(KEY|VALUE)_(\d+)", name, re.I)
            if pair:
                gitcfg.setdefault(pair.group(2), {})[pair.group(1).upper()] = value
            elif name.upper() == "GIT_CONFIG_PARAMETERS":
                for key, val in re.findall(r"'([^']+)'='([^']*)'", value):
                    calls.extend(_git_transport_calls(["-c", f"{key}={val}"], hosts, depth))
            else:
                calls.extend(_value_calls(name, value, hosts, depth))
        elif tok.startswith("--") and "=" in tok:
            name, _, value = tok.partition("=")
            calls.extend(_value_calls(name, value, hosts, depth))
    for pair in gitcfg.values():
        if pair.get("KEY") is not None:
            calls.extend(_git_transport_calls(["-c", f"{pair['KEY']}={pair.get('VALUE', '')}"], hosts, depth))
    return calls


def _std_ssh_config(value: str, assigned: dict[str, list[str]]) -> bool:
    """-F <file>: ~/.ssh/config, none, or a file matching a configured standard_ssh_configs regex; $VAR is resolved inside the command."""
    ref = re.fullmatch(r"\$\{?([A-Za-z_]\w*)\}?", value.strip("'\""))
    candidates = assigned.get(ref.group(1), []) if ref else [value]
    return any(STD_SSH_CONFIG_RE.search(c.strip("'\"")) for c in candidates)


def _transport_ok(value: str, proxy: bool = False) -> bool:
    """A plain ssh used as a transport (GIT_SSH_COMMAND, rsync -e, scp -S, ProxyCommand): ssh/plink with identity,
    port, config and safe -o options only; a ProxyCommand may also be `ssh -W %h:%p jump` or `nc %h %p`."""
    toks = _tokens(value)
    if not toks:
        return True
    if any(t in SEPARATORS or t[:1] in "<>" for t in toks):
        return False
    name = _prog_name(toks[0])
    if proxy and name in ("nc", "ncat", "netcat", "socat", "connect", "connect-proxy", "corkscrew"):
        return "%h" in value and not any(t in ("-e", "-c", "--exec", "--sh-exec", "--lua-exec") or
                                         t.upper().startswith(("EXEC:", "SYSTEM:")) for t in toks)
    if name not in ("ssh", "plink"):
        return False
    k, positional, stdio = 1, [], False
    while k < len(toks):
        t = toks[k]
        if name == "plink" and t.startswith("-"):
            if t in ("-R", "-L", "-D", "-proxycmd", "-m"):
                return False
            k += 2 if t in PLINK_ARG_OPTS else 1
        elif t.startswith("-") and len(t) > 1:   # v8: getopt clusters (-qW %h:%p, -vo BatchMode=yes)
            opts, used = _cluster(t, toks[k + 1] if k + 1 < len(toks) else None, SSH_ARG_OPTS)
            for opt, val in opts:
                if opt in ("-L", "-R", "-D", "-w") or (opt == "-o" and not _o_safe(val)):
                    return False
                stdio = stdio or opt == "-W"
            k += used
        else:
            positional.append(t)
            k += 1
    return not positional or (proxy and stdio and len(positional) == 1)


def _transport_calls(name: str, value: str, hosts: dict[str, str], depth: int, proxy: bool = False) -> list[dict]:
    """Nested ssh calls inside a transport command, plus an opaque-transport call when it is not a plain ssh."""
    calls = parse_remote_calls(value, hosts, depth + 1) if depth < 4 and RAW_REMOTE_RE.search(value) else []
    if not _transport_ok(value, proxy):
        calls.append(_call(name, hosts, value, f"transport-command:{name}", "transport"))
    else:                                          # v10: GIT_SSH_COMMAND='ssh -F /tmp/x.cfg' warns like ssh -F
        toks = _tokens(value)
        for k, t in enumerate(toks):
            if t.startswith("-") and not t.startswith("--"):
                opts, _ = _cluster(t, toks[k + 1] if k + 1 < len(toks) else None, SSH_ARG_OPTS)
                if any(o == "-F" and not _std_ssh_config(v, {}) for o, v in opts):
                    calls.append(_call(name, hosts, value, "ssh-config-file", "transport", soft=True))
    return calls


def _copy_option_calls(name: str, args: list[str], hosts: dict[str, str], depth: int) -> list[dict]:
    """rsync -e/--rsh/--rsync-path/-M, scp/sftp -S program and -o options; v8: getopt clusters (-ave X, -qS X, -qoX)."""
    letters = {"scp": "cDFiJloPSX", "sftp": "BbcDFiJloPRSsX", "rsync": "eBTfM"}.get(name)
    calls, k = [], 0

    def rsync_path(value: str) -> None:
        if not re.fullmatch(r"(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?rsync", value.strip()):
            calls.append(_call("rsync --rsync-path", hosts, value, "rsync-path-command", "transport"))

    while k < len(args):
        a, nxt = args[k], (args[k + 1] if k + 1 < len(args) else None)
        if a.startswith("--") and name == "rsync":
            opt, eq, val = a.partition("=")
            if not eq and opt in ("--rsh", "--rsync-path", "--remote-option") and nxt is not None:
                val, k = nxt, k + 1
            if opt == "--rsh":
                calls += _transport_calls("rsync --rsh", val, hosts, depth)
            elif opt == "--rsync-path":
                rsync_path(val)
            elif opt == "--remote-option" and val.startswith("--rsync-path"):
                rsync_path(val.partition("=")[2])
            k += 1
        elif a.startswith("-") and len(a) > 1 and not a.startswith("--") and letters is not None:
            opts, used = _cluster(a, nxt, letters)
            for opt, val in opts:
                if opt == "-e" and name == "rsync":
                    calls += _transport_calls("rsync -e", val, hosts, depth)
                elif opt == "-M" and name == "rsync" and val.startswith("--rsync-path"):
                    rsync_path(val.partition("=")[2])
                elif opt == "-S" and name in ("scp", "sftp"):
                    calls += _transport_calls(f"{name} -S", val, hosts, depth)
                elif opt == "-o" and name in ("scp", "sftp"):
                    key, v = _ssh_option(val)
                    if key in SSH_OPTION_COMMANDS and not (key == "proxycommand" and v.strip().lower() == "none"):
                        calls += _transport_calls(f"{name} -o {key}", v, hosts, depth, proxy=key == "proxycommand")
                    elif not _o_safe(val) and key not in SSH_OPTION_COMMANDS:
                        calls.append(_call(f"{name} -o {key}", hosts, "", f"ssh-option:{key}", "transport"))
            k += used
        else:
            k += 1
    return calls


def _sched_reason(words: list[str]) -> str | None:
    """ionice/chrt/taskset that change ANOTHER process (or set a realtime policy) are changes; query forms are reads."""
    n = _prefix_len(words)
    for k, w in enumerate(words[:n]):
        if _prog_name(w) == "ionice":
            opts = []
            j = k + 1
            while j < n and words[j].startswith("-"):
                opts.append(words[j])
                j += 2 if words[j] in ("-c", "-n", "-p", "-P", "-u") else 1
            if any(o.startswith(("-p", "-P", "-u", "--pid", "--pgid", "--uid")) for o in opts) and \
                    any(o.startswith(("-c", "-n", "--class")) for o in opts):
                return "ionice-other-process"
    if not words[n:]:
        return None
    name, args = _prog_name(words[n]), words[n + 1:]
    if name == "chrt":
        if any(re.fullmatch(r"-[A-Za-z]*[frd][A-Za-z]*|--(?:fifo|rr|deadline)", a) for a in args):
            return "chrt-realtime"
        if any(re.fullmatch(r"-[A-Za-z]*p[A-Za-z]*|--pid", a) for a in args) and len(_pos(args, ("-T", "-P", "-D"))) > 1:
            return "chrt-other-process"
    if name == "taskset" and any(re.fullmatch(r"-[A-Za-z]*p[A-Za-z]*|--pid", a) for a in args) and len(_pos(args)) > 1:
        return "taskset-other-process"
    return None


def _sched_wrapped(name: str, args: list[str]) -> list[str] | None:
    """chrt [opts] prio cmd… / taskset [opts] mask cmd… (query forms -p PID run nothing)."""
    if name not in ("chrt", "taskset"):
        return None
    pos = _pos(args, ("-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"))
    if any(re.fullmatch(r"-[A-Za-z]*p[A-Za-z]*|--pid", a) for a in args) or any(a in ("-m", "--max") for a in args):
        return [""]                                       # query only (changes were caught by _sched_reason)
    return [_rejoin(pos[1:])] if len(pos) > 1 else []


# ---------------------------------------------------------------------------------------------------------------
# v10 (review round 9): values that carry a command are only those in command-carrier positions;
# strings executed at run time (PowerShell iex/scriptblock/& $var, bash $VAR, watch/script/expect/at/env -S, read/
# mapfile) are judged as commands; git push to a known host changes that host.
# ---------------------------------------------------------------------------------------------------------------
CARRIER_OPTIONS = {"--rsh", "--rsync-path", "--upload-pack", "--receive-pack", "--exec", "--command", "--split-string",
                   "--proxy-command", "--ssh-command", "--rsh-command", "--shell-command", "--filter"}
PS_VAR_SET_RE = re.compile(r"(?i)\$(\w+)\s*=\s*(?:'([^']*)'|\"([^\"]*)\")"
                           r"|\b(?:Set-Variable|sv)\s+(?:-Name\s+)?['\"]?(\w+)['\"]?\s+(?:-Value\s+)?(?:'([^']*)'|\"([^\"]*)\")")
DYNAMIC_REF_RE = re.compile(r"\"?\$\{?([A-Za-z_]\w*)(?:\[[^\]]*\])?\}?\"?")


def _ps_dynamic_calls(command: str, hosts: dict[str, str], depth: int) -> list[dict]:
    """PowerShell strings executed at run time: Invoke-Expression/iex, [scriptblock]::Create, & $var."""
    variables, calls = {}, []
    for m in PS_VAR_SET_RE.finditer(command):
        if m.group(1):
            variables[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
        else:
            variables[m.group(4).lower()] = m.group(5) if m.group(5) is not None else m.group(6)

    def judge(text: str | None, label: str, args: str = "") -> None:
        if text is None:
            calls.append(_call(label, hosts, args, f"dynamic-command:{label}", "transport"))
        elif depth < 4 and RAW_REMOTE_RE.search(text + " " + args):
            calls.extend(parse_remote_calls((text + " " + args).strip(), hosts, depth + 1, ps=True))

    for rx, label in ((r"\b(?:Invoke-Expression|iex)\s+(?:-Command\s+)?", "iex"), (r"\[scriptblock\]::Create\(\s*", "scriptblock")):
        for m in re.finditer(r"(?i)" + rx + r"(?:'([^']*)'|\"([^\"]*)\"|\$(\w+))", command):
            text = m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else \
                variables.get(m.group(3).lower())
            judge(text, label)                    # an unresolved iex $x executes an unknown string: opaque
    for m in re.finditer(r"(?:^|[;|{(\s])&\s*\$(\w+)([^;|\n}]*)", command):
        value = variables.get(m.group(1).lower())
        if value is not None or _reaches_host(m.group(1), m.group(2).split(), hosts):
            judge(value, "& $" + m.group(1), m.group(2).strip())
    return calls


def _reaches_host(name: str, args: list[str], hosts: dict[str, str]) -> bool:
    """An unresolved dynamic command can reach a transport when its name says so or an argument is a known host."""
    return bool(re.search(r"(?i)ssh|rsh|scp|plink|rsync", name)) or any(
        hosts.get(_host_of(a.strip("'\"")).lower()) for a in args if a and not a.startswith("-"))


def _git_url_host(url: str) -> str | None:
    """ssh://[user@]host[:port]/path or [user@]host:path (scp-like) -> host; local paths -> None."""
    m = re.match(r"(?i)(?:ssh|git\+ssh|ssh\+git)://(?:[^@/]+@)?(\[[^\]]+\]|[^:/]+)", url)
    if m:
        return m.group(1).strip("[]")
    m = re.match(r"(?:[^@/:\s]+@)?([A-Za-z0-9_.-]{2,}):(?!//)", url)
    return m.group(1) if m else None


def _git_push_calls(cfg: dict[str, str], rest: list[str], hosts: dict[str, str]) -> list[dict]:
    """git push to a repository on a known host (URL, -c remote.X.url, -c url.B.insteadOf=P) changes that host."""
    pos = _pos(rest, ("--repo", "-o", "--push-option", "--receive-pack", "--exec", "--signed", "--force-with-lease"))
    repo = next((a.partition("=")[2] for a in rest if a.startswith("--repo=")), pos[0] if pos else "")
    repo = cfg.get(f"remote.{repo.lower()}.url", repo)
    for key, prefix in cfg.items():
        m = re.fullmatch(r"url\.(.+)\.insteadof", key)
        if m and prefix and repo.startswith(prefix):
            repo = m.group(1) + repo[len(prefix):]
    host = _git_url_host(repo) if repo else None
    if host and hosts.get(host.lower()):
        return [_call(host, hosts, f"git push {repo}", "git-push", "git")]
    return []


def _run_strings(raw: list[str], seg: list[str], prev: list[str] | None, assigned: dict[str, list[str]],
                 hosts: dict[str, str]) -> tuple[list[str], list[dict]]:
    """Strings a local command will execute: watch/script/expect/at/env -S/herestrings/echo-pipes, a quoted
    multi-word command word, $VAR as a command (resolved from this command's assignments, read and mapfile)."""
    snippets, calls = [], []
    n = _prefix_len(raw)
    for k, w in enumerate(raw[:n]):                # env -S 'cmd' / --split-string=cmd as a prefix
        if _prog_name(w) == "env":
            for j in range(k + 1, n):
                a = raw[j]
                if a in ("-S", "--split-string") and j + 1 < len(raw):
                    snippets.append(raw[j + 1])
                elif re.match(r"-S.|--split-string=", a):
                    snippets.append(a.partition("=")[2] if a.startswith("--") else a[2:])
    if not seg:
        return snippets, calls
    name, args = _prog_name(seg[0]), seg[1:]
    # 'ssh host rm x' used as the command word (after watch/flock/tmux …); $(…) text is judged by _substitutions
    if re.search(r"\s", seg[0]) and not re.match(r"(?:[A-Za-z_]\w*=)?(?:\$\(|\(|`)", seg[0]):
        snippets.append(seg[0] + (" " + _rejoin(args) if args else ""))
    if name == "script":                           # script -qc CMD /dev/null
        k = 0
        while k < len(args) and args[k].startswith("-"):
            if args[k] == "--command" and k + 1 < len(args) or args[k].startswith("--command="):
                snippets.append(args[k].partition("=")[2] or args[k + 1])
                break
            opts, used = _cluster(args[k], args[k + 1] if k + 1 < len(args) else None, "cTBIOEmo")
            snippets += [v for o, v in opts if o == "-c"]
            k += used
    if name == "expect":                           # expect -c 'spawn ssh …; exec …'
        for k, a in enumerate(args[:-1]):
            if a == "-c":
                snippets += re.findall(r"\b(?:spawn|exec)\s+(?:-\w+\s+)*([^;\n\]}]+)", args[k + 1])
    if name in ({"at", "batch"} | SHELLS) and "<<<" in raw:   # at now <<< CMD, bash <<< CMD
        k = raw.index("<<<")
        snippets += raw[k + 1:k + 2]
    if prev and _prog_name(prev[0]) in ("echo", "printf") and name in ({"at", "batch"} | SHELLS):
        snippets.append(" ".join(a for a in prev[1:] if not a.startswith("-")))   # echo CMD | at now / | sh
    ref = DYNAMIC_REF_RE.fullmatch(seg[0])
    if ref:                                        # $C / "${A[0]}" as the command word
        values = assigned.get(ref.group(1))
        if values:
            snippets.append(values[-1] + (" " + _rejoin(args) if args else ""))
        elif _reaches_host(ref.group(1), args, hosts):
            calls.append(_call("$" + ref.group(1), hosts, " ".join(seg), f"dynamic-command:${ref.group(1)}", "transport"))
    return snippets, calls


def _startup_file_calls(command: str, calls: list[dict], hosts: dict[str, str]) -> list[dict]:
    """BASH_ENV=/x / ENV=/x before a shell that also calls a remote host: the file's content is not visible -> warn."""
    if not re.search(r"(?:^|[\s;&|])(?:export\s+)?(?:BASH_ENV|ENV)=\S", command):
        return []
    return [_call(h, hosts, "", "opaque-startup-file:BASH_ENV", "ssh", soft=True) for h in sorted({c["host_token"] for c in calls})]


def parse_remote_calls(command: str, hosts: dict[str, str], _depth: int = 0, _stdin: bool = False,
                       ps: bool = False) -> list[dict]:
    """[{host_token, host, remote, mutating, reason, kind}] for every ssh/plink/scp/sftp/rsync call."""
    tokens = _tokens(command, ps)
    calls, seen = [], set()
    assigned: dict[str, list[str]] = {}
    for tok in tokens:                             # v9: NAME=V values (for ssh -F $F) …
        match = re.fullmatch(r"([A-Za-z_]\w*)\+?=(.*)", tok, re.S)
        if match:
            assigned.setdefault(match.group(1), []).append(match.group(2))
    for seg in _segments(command):                 # v10: read -r C <<< V / mapfile -t A <<< V
        if seg and _prog_name(seg[0]) in ("read", "mapfile", "readarray") and "<<<" in seg[:-1]:
            k = seg.index("<<<")
            for nm in [w for w in seg[1:k] if re.fullmatch(r"[A-Za-z_]\w*", w)]:
                assigned.setdefault(nm, []).append(seg[k + 1])
                calls.extend(_value_calls(nm, seg[k + 1], hosts, _depth) if _depth < 4 else [])
    if _depth < 4:                                 # … and the generic value detector (any NAME=V, --opt=V, GIT_CONFIG_*)
        calls.extend(_assignment_calls(tokens, hosts, _depth))
    if _depth < 4:                                 # v3: $(ssh ...) / `ssh ...`, also inside "..."
        for sub in _substitutions(_strip_heredocs(command), ps):
            if RAW_REMOTE_RE.search(sub):
                calls.extend(parse_remote_calls(sub, hosts, _depth + 1))
    text = _strip_heredocs(command)                # v10: heredoc bodies are data for the raw-text scanners too
    if WIN_GATE_RE.search(text):
        calls.extend(_ps_remote_calls(text, hosts, _depth))
    if re.search(r"(?i)\biex\b|invoke-expression|scriptblock|&\s*\$", text):
        calls.extend(_ps_dynamic_calls(text, hosts, _depth))      # v10: iex 'X', [scriptblock]::Create, & $c
    if re.search(r"(?i)env:|SetEnvironmentVariable", text):
        calls.extend(_ps_env_calls(text, hosts, _depth))          # v8: $env:GIT_SSH_COMMAND=…
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        name = _prog_name(tok)
        at_command = _command_position(tokens, i)
        if (name in SSH_TOOLS or name in COPY_TOOLS or name == "sftp") and not at_command:
            i += 1                                 # e.g. "echo ssh host rm x": an argument, not a call
            continue
        seg_start = i == 0 or tokens[i - 1] in SEPARATORS
        if (at_command or seg_start) and _depth < 4:   # v3: bash -c "ssh …"; v10: also prefix-only segments (env -S)
            j = i
            while j < len(tokens) and tokens[j] not in SEPARATORS:
                j += 1
            seg = _strip_prefix(tokens[i:j])
            if not seg and seg_start:
                calls.extend(c for snip in _run_strings(tokens[i:j], [], None, assigned, hosts)[0]
                             if RAW_REMOTE_RE.search(snip) for c in parse_remote_calls(snip, hosts, _depth + 1))
            if seg and j - len(seg) not in seen:
                seen.add(j - len(seg))
                prev = None                        # v10: the command piped into this one (echo X | at now)
                if i > 0 and tokens[i - 1] == "|":
                    k = i - 2
                    while k >= 0 and tokens[k] not in SEPARATORS:
                        k -= 1
                    prev = _strip_prefix(tokens[k + 1:i - 1])
                run_snippets, run_calls = _run_strings(tokens[i:j], seg, prev, assigned, hosts)
                calls.extend(run_calls)
                for snippet in run_snippets:
                    if RAW_REMOTE_RE.search(snippet) or DYNAMIC_REF_RE.search(snippet):
                        calls.extend(parse_remote_calls(snippet, hosts, _depth + 1))
                if _prog_name(seg[0]) == "git":       # v8/v9: git -c KEY=V, git config KEY V, --upload-pack, foreach…
                    calls.extend(_git_transport_calls(seg[1:], hosts, _depth))
                elif _prog_name(seg[0]) == "printf" and "-v" in seg[:-2]:   # v9: printf -v NAME FMT ARGS
                    k = seg.index("-v")
                    fmt, fargs = seg[k + 2], seg[k + 3:]
                    value = fmt.replace("%s", " ".join(fargs), 1) if "%s" in fmt and fargs else (" ".join(fargs) or fmt)
                    calls.extend(_value_calls(seg[k + 1], value, hosts, _depth))
                elif _prog_name(seg[0]) == "set" and len(seg) > 1 and "=" in seg[1] and not seg[1].startswith("-"):
                    name, _, first = seg[1].partition("=")     # v9: cmd.exe set NAME=rest of the line
                    calls.extend(_value_calls(name, " ".join([first] + seg[2:]), hosts, _depth))
                for snippet in _embedded(seg)[1] + (_wrapped(_prog_name(seg[0]), seg[1:]) or []):
                    if RAW_REMOTE_RE.search(snippet):
                        calls.extend(parse_remote_calls(snippet, hosts, _depth + 1))
        if name in SSH_TOOLS:
            j, dest, opts_seen = i + 1, None, []
            plink = name in ("plink", "putty", "kitty")
            value_letters = SSH_ARG_OPTS | ({"M"} if name == "autossh" else set())
            while j < len(tokens) and tokens[j] not in SEPARATORS:
                t = tokens[j]
                if t == "--" and not plink:        # v4: "ssh host -- rm x" ends the options
                    j += 1
                    if dest is None:
                        continue
                    break
                # v4: OpenSSH also parses options AFTER the host (ssh host -p 22 rm x); plink does not
                if t.startswith("-") and len(t) > 1 and (dest is None or not plink):
                    if plink:
                        takes = t in PLINK_ARG_OPTS
                        opts_seen.append((t, tokens[j + 1] if takes and j + 1 < len(tokens) else ""))
                        j += 2 if takes else 1
                        continue
                    # v8: real getopt: -vo X, -qoBatchMode=yes, -R9000:h:22, -fNR spec, -vp 22
                    nxt = tokens[j + 1] if j + 1 < len(tokens) and tokens[j + 1] not in SEPARATORS else None
                    opts, used = _cluster(t, nxt, value_letters)
                    opts_seen += opts
                    j += used
                    continue
                if dest is None:
                    dest = t
                    j += 1
                    continue
                break
            jump, remote_command, no_session, opt_hard, opt_soft, host_override = [], None, False, "", "", None
            for opt, value in opts_seen:
                if plink:
                    if opt == "-m":                # v5: plink/putty -m file: the remote command is in a file
                        remote_command = "__remote-command-file__"
                    elif opt == "-proxycmd" and not _transport_ok(value, proxy=True):
                        opt_hard = opt_hard or "plink-proxycmd"
                    elif opt == "-R":
                        opt_hard = opt_hard or "ssh-forward:-R"
                    elif opt in ("-L", "-D"):
                        opt_soft = opt_soft or f"ssh-forward:{opt}"
                    continue
                if opt == "-o":                    # every -o key is checked (allowlist), any spelling/case
                    match = re.match(r"(?is)\s*RemoteCommand\s*[=\s]\s*(.+)", value)
                    remote_command = match.group(1) if match else remote_command
                    key, val = _ssh_option(value)
                    if key in SSH_OPTION_COMMANDS and not (key == "proxycommand" and val.strip().lower() == "none"):
                        transport = _transport_calls(f"ssh -o {key}", val, hosts, _depth, proxy=key == "proxycommand")
                        calls.extend(c for c in transport if c["kind"] != "transport")
                        if key != "proxycommand" or any(c["kind"] == "transport" for c in transport):
                            opt_hard = opt_hard or f"ssh-option:{key}"
                    elif key == "hostname":
                        host_override = val        # -o HostName=192.0.2.20 decides the real target
                    elif key in ("localforward", "dynamicforward"):
                        opt_soft = opt_soft or "ssh-forward-local"
                    elif not _o_safe(value) and key != "remotecommand":
                        opt_hard = opt_hard or f"ssh-option:{key}"
                elif opt in ("-R", "-w"):          # v7: reverse tunnel / tun device change the remote side
                    opt_hard = opt_hard or f"ssh-forward:{opt}"
                elif opt in ("-L", "-D"):
                    opt_soft = opt_soft or f"ssh-forward:{opt}"
                elif opt == "-J":
                    jump.append(value)
                elif opt == "-I":                  # v9: a PKCS#11 library is loaded code (like -o PKCS11Provider)
                    opt_hard = opt_hard or "ssh-option:-I"
                elif opt == "-F" and not _std_ssh_config(value, assigned):
                    opt_soft = opt_soft or "ssh-config-file"   # v9: a non-standard config may hold ProxyCommand…
                no_session = no_session or opt in ("-G", "-V", "-W", "-N", "-O", "-Q")
            rest = []
            stdin_fed = (i > 0 and tokens[i - 1] == "|") or (_stdin and not any(t in SEPARATORS for t in tokens[:i]))
            while j < len(tokens) and tokens[j] not in SEPARATORS:
                t = tokens[j]
                if t[:1] in "<>":
                    # Unquoted redirections belong to the local shell: "> file" writes locally,
                    # "< file" / heredoc feeds the remote command's stdin. Skip the operand too.
                    stdin_fed = stdin_fed or t.startswith("<")
                    if rest and rest[-1].isdigit():
                        rest.pop()
                    j += 1 if t.endswith("&") else 2
                    continue
                rest.append(t)
                j += 1
            remote = " ".join(rest) or remote_command or ""
            if dest and not no_session:
                inner = (parse_remote_calls(remote, hosts, _depth + 1, stdin_fed)
                         if _depth < 3 and RAW_REMOTE_RE.search(remote) else [])
                calls.extend(inner)                # the outer host is transport for nested calls ...
                guests, own = _guest_calls(remote, hosts) if re.search(r"\b(?:pct|qm)\b", remote) else ([], remote)
                calls.extend(guests)               # v4: pct/qm exec into a mapped guest locks the guest
                interactive = not remote or INTERACTIVE_RE.fullmatch(remote.strip())
                soft = False
                if inner or guests:
                    reason = remote_is_mutating(own)   # ... and is locked only when it changes itself
                elif stdin_fed and (interactive or STDIN_SCRIPT_RE.search(remote)):
                    reason = "stdin-script"
                elif interactive:
                    reason, soft = "interactive-session", True   # v4: warn even in enforce
                elif remote == "__remote-command-file__":
                    reason = "remote-command-file"
                else:
                    reason = remote_is_mutating(own)
                if opt_hard and (not reason or soft):
                    reason, soft = opt_hard, False         # v7: ProxyCommand/LocalCommand/-R/-w/unknown -o key
                elif opt_soft and not reason:
                    reason, soft = opt_soft, True          # v7: -L/-D local forwarding only warns
                if reason or not (inner or guests):
                    calls.append(_call(_host_of(host_override or dest), hosts, remote, reason, "ssh", soft))
            elif dest and (opt_hard or opt_soft):         # -N/-W/-G: no remote command, but tunnels/options count
                calls.append(_call(_host_of(host_override or dest), hosts, "", opt_hard or opt_soft, "ssh", not opt_hard))
            i = j
            continue
        if name == "sftp":                         # v3: an sftp session or batch can put/rm/rename
            j, positional, batch = i + 1, [], False
            while j < len(tokens) and tokens[j] not in SEPARATORS:
                t = tokens[j]
                if t[:1] in "<>":
                    batch = batch or t.startswith("<")
                    j += 1 if t.endswith("&") else 2
                elif t.startswith("-") and len(t) > 1:  # v8: getopt (-qo X host, -b- host)
                    nxt = tokens[j + 1] if j + 1 < len(tokens) and tokens[j + 1] not in SEPARATORS else None
                    opts, used = _cluster(t, nxt, SFTP_ARG_OPTS)
                    batch = batch or any(o == "-b" for o, _ in opts)
                    j += used
                else:
                    positional.append(t)
                    j += 1
            batch = batch or (i > 0 and tokens[i - 1] == "|")
            calls.extend(_copy_option_calls("sftp", tokens[i + 1:j], hosts, _depth))   # v7
            if positional:
                first = positional[0]
                download = _is_remote_path(first) and not first.endswith(("/", ":")) and not batch
                if not download:
                    calls.append(_call(_host_of(first), hosts, "", "sftp-batch" if batch else "sftp-session", "copy"))
            i = j
            continue
        if name in COPY_TOOLS:
            j, args = i + 1, []
            while j < len(tokens) and tokens[j] not in SEPARATORS and tokens[j][:1] not in "<>":
                args.append(tokens[j])
                j += 1
            if args and args[-1].isdigit() and j < len(tokens) and tokens[j][:1] in "<>":
                args.pop()                         # v3: "scp f host:/x 2>&1" - the 2 belongs to the redirect
            while j < len(tokens) and tokens[j] not in SEPARATORS:
                j += 1
            calls.extend(_copy_option_calls(name, args, hosts, _depth))   # v7: rsync -e, scp -S/-o
            positional = [a for a in args if not a.startswith("-")]
            if positional:
                dest = positional[-1]
                if _is_remote_path(dest):
                    calls.append(_call(_host_of(dest), hosts, "", f"{name}-upload", "copy"))
            i = j
            continue
        i += 1
    if _depth == 0 and calls:
        calls.extend(_startup_file_calls(text, calls, hosts))      # v10: BASH_ENV=/x.sh bash -c 'ssh …'
    return calls


def _parse_utc(value: str) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def live(lock: dict, now: dt.datetime) -> bool:
    if lock.get("status", "active") != "active":
        return False
    expires = _parse_utc(str(lock.get("expires_utc") or ""))
    return expires is None or expires > now   # Integrity treats '' as no expiry


def decide(tool: str, tool_input: dict, session: str, state: dict | None, hosts: dict[str, str],
           mode: str = "shadow", now: dt.datetime | None = None) -> dict:
    """Return {"decision": allow|warn|deny, "reason": str, "hosts": [...]}."""
    now = now or dt.datetime.now(UTC)
    command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    if tool not in SHELL_TOOLS or not command:
        return {"decision": "allow", "reason": "not-a-shell-action", "hosts": []}
    calls = [c for c in parse_remote_calls(command, hosts, ps=tool == "PowerShell") if c["mutating"]
             and c["host_token"].lower() not in LOCALHOSTS]
    if not calls:
        return {"decision": "allow", "reason": "read-only-or-local", "hosts": []}
    # v4: an interactive session (ssh host, sudo -i, Enter-PSSession) only warns, even in enforce
    block = "deny" if mode == "enforce" and any(not c.get("soft") for c in calls) else "warn"
    transport = [c for c in calls if c["kind"] == "transport"]
    if transport:                                  # v7: the target host of such a transport is not visible
        return {"decision": block, "hosts": [],
                "reason": f"opaque-ssh-transport {transport[0]['reason']}: {transport[0]['remote'][:80]!r}. Use a plain ssh "
                          "(-i/-p/-F/-o BatchMode…) as transport; ProxyCommand/LocalCommand/GIT_SSH_COMMAND with a command "
                          "need an operator decision."}
    unknown = sorted({c["host_token"] for c in calls if not c["host"]})
    if unknown:
        return {"decision": block, "hosts": unknown,
                "reason": f"unknown-host {','.join(unknown)} with a changing command: add it to the lock-guard host table "
                          "(canonical id) and take an Integrity lock first."}
    targets = sorted({c["host"] for c in calls})
    # v11: until the server accepts kind=lock no agent can take an own lock, so these two warnings
    # could never be acted on; shadow mode stays silent.
    if not SERVER_LOCK_KIND and mode == "shadow" and (state is None or not any(
            lock.get("owner_session_id") != session and set(lock.get("target_hosts") or []) & set(targets)
            for lock in state.get("locks", []) if live(lock, now))):
        return {"decision": "allow", "reason": "own-lock-unavailable-shadow", "hosts": targets}
    if state is None:
        return {"decision": block, "hosts": targets,
                "reason": "lock-state-unknown: no Integrity coordination snapshot cached for this session; "
                          "run integrity_context_admission and take a lock (kind=lock) before changing "
                          + ",".join(targets)}
    locks = [lock for lock in state.get("locks", []) if live(lock, now)]
    foreign = [lock for lock in locks if lock.get("owner_session_id") != session
               and set(lock.get("target_hosts") or []) & set(targets)]
    if foreign:
        lock = foreign[0]
        return {"decision": block, "hosts": targets,
                "reason": (f"host-locked: {','.join(sorted(set(lock['target_hosts']) & set(targets)))} "
                           f"held by {lock.get('owner_actor') or lock.get('owner_session_id') or 'unknown'} "
                           f"lock={lock.get('lock_id')} task={lock.get('task_id')} until {lock.get('expires_utc') or 'no-expiry'}: "
                           f"{lock.get('reason', '')}. Coordinate on the bus or ask the operator; "
                           f"if it was just released, refresh admission (snapshot {state.get('snapshot_at', '?')}).")}
    covered = set()
    for lock in locks:
        if lock.get("owner_session_id") == session:
            covered |= set(lock.get("target_hosts") or [])
    missing = [h for h in targets if h not in covered]
    if missing:
        return {"decision": block, "hosts": targets,
                "reason": (f"no-own-lock for {','.join(missing)}: append an Integrity lock first "
                           "(integrity_append_event kind=lock lock_action=acquire target_hosts=[...] ttl_minutes<=120 reason=...).")}
    return {"decision": "allow", "reason": "own-lock-covers-targets", "hosts": targets}


def _state_path(session: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session or "unknown")[:120]
    return STATE_DIR / f"{safe}.json"


def load_state(session: str) -> dict | None:
    try:
        return json.loads(_state_path(session).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def record(payload: dict) -> None:
    """PostToolUse: cache admission active_locks and own lock receipts for this session."""
    tool = str(payload.get("tool_name") or "")
    session = str(payload.get("session_id") or "")
    if "integrity" not in tool:
        return
    response = payload.get("tool_response")
    text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False)
    flat = text.replace('\\"', '"')  # the response may carry the admission JSON as an escaped string
    match = re.search(r'"active_locks"\s*:\s*\[', flat)
    state = load_state(session) or {"session_id": session, "locks": [], "own": []}
    if "context_admission" in tool and match:
        try:
            snapshot, _ = json.JSONDecoder().raw_decode(flat, match.end() - 1)
        except ValueError:
            return
        if not isinstance(snapshot, list):
            return
        own_ids = {lock.get("lock_id") for lock in state.get("own", [])}
        state["locks"] = [lock for lock in snapshot if lock.get("lock_id") not in own_ids] + state.get("own", [])
        state["snapshot_at"] = dt.datetime.now(UTC).isoformat()
    elif "append_event" in tool and '"lock_action"' in json.dumps(payload.get("tool_input") or {}):
        details = (payload.get("tool_input") or {}).get("details") or {}
        lock = {"lock_id": details.get("lock_id"), "task_id": details.get("task_id"), "owner_session_id": session,
                "owner_actor": "self", "target_hosts": details.get("target_hosts") or [], "status": "active",
                "reason": details.get("reason", ""),
                "expires_utc": (dt.datetime.now(UTC) + dt.timedelta(minutes=min(float(details.get("ttl_minutes") or 60), 120))).isoformat()}
        own = [x for x in state.get("own", []) if x.get("lock_id") != lock["lock_id"]]
        if details.get("lock_action") != "release":
            own.append(lock)
        state["own"] = own
        state["locks"] = [x for x in state.get("locks", []) if x.get("owner_session_id") != session] + own
    else:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _state_path(session).with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, _state_path(session))


def hook_output(result: dict) -> dict:
    """Claude Code PreToolUse JSON; other harnesses use --exit-code (deny -> exit 2)."""
    if result["decision"] == "allow":
        return {}
    text = f"INTEGRITY LOCK GUARD {result['decision'].upper()}: {result['reason']}"
    if result["decision"] == "deny":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": text}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": text}}


def main(argv: list[str]) -> int:
    payload = json.load(sys.stdin)
    if "record" in argv:
        try:
            record(payload)
        except Exception:
            pass                               # a cache failure must never affect the turn
        return 0
    mode = "enforce" if "--enforce" in argv else "shadow"
    session = str(payload.get("session_id") or "")
    tool_input = payload.get("tool_input") or {}
    try:
        try:
            hosts = load_hosts()
        except (OSError, ValueError, KeyError):
            hosts = {}
        result = decide(str(payload.get("tool_name") or ""), tool_input, session, load_state(session), hosts, mode)
    except Exception as exc:  # never crash a turn; fail closed only for remote changes
        raw = str(tool_input.get("command") or "")
        risky = bool(RAW_REMOTE_RE.search(raw)) and any(w in raw for w in ("rm ", "systemctl", "virsh", "reboot", ">", "install", "apt"))
        result = {"decision": ("deny" if mode == "enforce" and risky else "warn"), "hosts": [],
                  "reason": f"guard-error {type(exc).__name__}"}
    print(json.dumps(hook_output(result), ensure_ascii=False))
    if "--exit-code" in argv and result["decision"] == "deny":
        print(result["reason"], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
