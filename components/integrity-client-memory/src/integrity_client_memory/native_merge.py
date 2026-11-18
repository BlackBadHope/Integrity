# SPDX-License-Identifier: BUSL-1.1
"""integrity-native-merge: merge a generated Native profile into user-scope settings.

``integrity-native-profile`` writes hooks and one MCP entry into an isolated
workspace and never touches active settings. This command takes the next step
on purpose: it verifies the profile, then merges its hook definitions and its
MCP entry into the user scope of Claude Code or Codex, preserving every
unrelated entry.

- Dry run by default. ``--apply`` writes; each changed file is first copied to
  ``<file>.integrity-backup-<UTC time>`` and then replaced atomically.
- Hook handlers that an earlier Native profile installed (commands that run
  ``integrity_client_memory.native_runtime ... hook``) are replaced, so a new
  profile switches the hooks instead of doubling them. Any other hook,
  including another Integrity plugin's, is kept and reported.
- ``--remove`` takes the Native hooks and the MCP entry out again.
- A file that is not valid JSON or TOML is refused, never overwritten.

Antigravity is not handled: its generated plugin is already user scope.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import native_runtime

VENDORS = ("claude", "codex")
NATIVE_MARKER = "integrity_client_memory.native_runtime"
MAX_FILE = 8 * 1024 * 1024
SERVER_NAMES = ("integrity_native", "integrity_client_memory")


def is_native_hook(handler: Any) -> bool:
    """A handler written by an Integrity Native profile, from any profile root."""
    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    words = handler["command"].replace('"', " ").replace("'", " ").split()
    return NATIVE_MARKER in words and "hook" in words


def _is_integrity(handler: Any) -> bool:
    return (isinstance(handler, dict) and isinstance(handler.get("command"), str)
            and "integrity" in handler["command"].lower())


def _load_json(path: Path) -> dict[str, Any] | None:
    """The document, None when the file does not exist; refuse anything unreadable."""
    if not path.exists() and not path.is_symlink():
        return None
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError(str(path) + " is not a regular settings file")
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError(str(path) + " is not valid JSON; fix it by hand first") from exc
    if not isinstance(document, dict):
        raise TypeError(str(path) + " must hold a JSON object")
    return document


def _load_text(path: Path) -> str | None:
    if not path.exists() and not path.is_symlink():
        return None
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError(str(path) + " is not a regular settings file")
    return path.read_text(encoding="utf-8-sig")


def merge_hooks(document: dict[str, Any] | None, generated: dict[str, Any], *, remove: bool = False
                ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the merged settings document and a summary of what changed."""
    result = copy.deepcopy(document) if document is not None else {}
    hooks = result.get("hooks", {})
    if not isinstance(hooks, dict):
        raise TypeError("settings key 'hooks' must be an object")
    hooks = {event: list(groups) if isinstance(groups, list) else groups for event, groups in hooks.items()}
    summary: dict[str, Any] = {"replaced": {}, "added": [], "removed": {}, "kept_other_integrity": {}}
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise TypeError("hooks for " + event + " must be a list")
        kept_groups, dropped = [], 0
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(inner, list):
                kept_groups.append(group)
                continue
            keep = [h for h in inner if not is_native_hook(h)]
            dropped += len(inner) - len(keep)
            others = sum(1 for h in keep if _is_integrity(h))
            if others:
                summary["kept_other_integrity"][event] = summary["kept_other_integrity"].get(event, 0) + others
            if keep:
                kept_groups.append({**group, "hooks": keep} if len(keep) != len(inner) else group)
        if dropped:
            summary["removed" if remove or event not in generated else "replaced"][event] = dropped
        hooks[event] = kept_groups
    if not remove:
        for event, groups in generated.items():
            if event not in summary["replaced"]:
                summary["added"].append(event)
            hooks.setdefault(event, []).extend(copy.deepcopy(groups))
    hooks = {event: groups for event, groups in hooks.items() if groups != []}
    if hooks:
        result["hooks"] = hooks
    else:
        result.pop("hooks", None)
    return result, summary


def merge_json_server(document: dict[str, Any] | None, name: str, entry: dict[str, Any] | None
                      ) -> tuple[dict[str, Any], str]:
    """Set (or with entry None, drop) mcpServers[name]; every other key is kept."""
    result = copy.deepcopy(document) if document is not None else {}
    servers = result.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise TypeError("settings key 'mcpServers' must be an object")
    servers = dict(servers)
    before = servers.get(name)
    if entry is None:
        servers.pop(name, None)
        action = "removed" if before is not None else "absent"
    else:
        servers[name] = copy.deepcopy(entry)
        action = "unchanged" if before == entry else ("replaced" if before is not None else "added")
    if servers or "mcpServers" in result:
        result["mcpServers"] = servers
    return result, action


def _section_re(name: str) -> re.Pattern[str]:
    quoted = re.escape(name)
    return re.compile(r"^\s*\[\s*mcp_servers\s*\.\s*(?:" + quoted + r'|"' + quoted + r'")\s*(?:\]|\.)')


def merge_toml_server(text: str | None, name: str, block: str | None) -> tuple[str, str]:
    """Replace (or drop) the [mcp_servers.<name>] table and its sub-tables in config.toml text."""
    text = text or ""
    try:
        before = (tomllib.loads(text).get("mcp_servers") or {}).get(name)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("config.toml is not valid TOML; fix it by hand first") from exc
    own, header = _section_re(name), re.compile(r"^\s*\[")
    lines, inside = [], False
    for line in text.splitlines(keepends=True):
        if header.match(line):
            inside = bool(own.match(line))
        if not inside:
            lines.append(line)
    if before is not None and lines == text.splitlines(keepends=True):
        # Defined inline (e.g. mcp_servers = { ... }): do not guess at an edit.
        raise ValueError("config.toml defines mcp_servers." + name + " in a form this command does not edit")
    merged = "".join(lines).rstrip("\n")
    if block is not None:
        merged = (merged + "\n\n" if merged else "") + block.rstrip("\n")
    merged = merged + "\n" if merged else ""
    after = (tomllib.loads(merged).get("mcp_servers") or {}).get(name)
    if block is None:
        action = "removed" if before is not None else "absent"
    else:
        action = "unchanged" if before == after else ("replaced" if before is not None else "added")
    return merged, action


def targets(vendor: str, home: Path, codex_home: Path | None) -> dict[str, Path]:
    if vendor == "claude":
        return {"hooks": home / ".claude" / "settings.json", "mcp": home / ".claude.json"}
    folder = codex_home or home / ".codex"
    return {"hooks": folder / "hooks.json", "mcp": folder / "config.toml"}


def _write(path: Path, data: str, stamp: str) -> str | None:
    """Back up the existing file, then replace it atomically with the same mode."""
    backup = None
    mode = 0o600
    if path.exists():
        mode = path.stat().st_mode & 0o777
        backup = path.with_name(path.name + ".integrity-backup-" + stamp)
        with open(backup, "xb") as copy_to, open(path, "rb") as source:
            shutil.copyfileobj(source, copy_to)
        os.chmod(backup, mode)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return str(backup) if backup else None


def plan(profile_path: Path, *, home: Path, codex_home: Path | None = None, remove: bool = False
         ) -> dict[str, Any]:
    """Verify the profile and compute every change without writing anything."""
    profile, root = native_runtime.verify(Path(profile_path))
    vendor = profile["vendor"]
    if vendor not in VENDORS:
        raise ValueError("vendor " + vendor + " needs no merge: its generated plugin is already user scope")
    name = profile.get("mcp_server_name", "integrity_native")
    if name not in SERVER_NAMES:
        raise ValueError("unexpected Native MCP server name")
    paths = targets(vendor, home, codex_home)
    changes: dict[str, Any] = {}
    if vendor == "claude":
        generated_hooks = _load_json(root / "claude-workspace/.claude/settings.json")["hooks"]
        servers = _load_json(root / "claude-workspace/.mcp.json")["mcpServers"]
        if set(servers) != {"integrity_native"}:
            raise ValueError("generated .mcp.json must hold exactly one integrity_native entry")
        current_mcp = _load_json(paths["mcp"])
        merged_mcp, mcp_action = merge_json_server(current_mcp, name, None if remove else servers["integrity_native"])
        mcp_text = json.dumps(merged_mcp, ensure_ascii=False, indent=2) + "\n"
        mcp_changed = (current_mcp or {}) != merged_mcp
    else:
        generated_hooks = _load_json(root / "codex-workspace/.codex/hooks.json")["hooks"]
        block = (root / "codex-workspace/.codex/config.toml").read_text(encoding="utf-8")
        current_text = _load_text(paths["mcp"])
        mcp_text, mcp_action = merge_toml_server(current_text, name, None if remove else block)
        mcp_changed = mcp_action not in {"unchanged", "absent"}
    current_hooks = _load_json(paths["hooks"])
    merged_hooks, hook_summary = merge_hooks(current_hooks, generated_hooks, remove=remove)
    hooks_changed = (current_hooks or {}) != merged_hooks
    changes["hooks"] = {"path": str(paths["hooks"]), "changed": hooks_changed, **hook_summary,
                        "text": json.dumps(merged_hooks, ensure_ascii=False, indent=2) + "\n"}
    changes["mcp"] = {"path": str(paths["mcp"]), "changed": mcp_changed, "server": name,
                      "action": mcp_action, "text": mcp_text}
    return {"vendor": vendor, "profile": str(Path(profile_path).absolute()),
            "mode": "remove" if remove else "merge", "changes": changes}


def apply(result: dict[str, Any]) -> dict[str, Any]:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    for change in result["changes"].values():
        change["backup"] = _write(Path(change["path"]), change["text"], stamp) if change["changed"] else None
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="integrity-native-merge", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", type=Path, required=True, help="profile.json written by integrity-native-profile")
    p.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    p.add_argument("--remove", action="store_true", help="remove the Native hooks and MCP entry instead")
    p.add_argument("--home", type=Path, help="home folder holding the user settings (default: your home)")
    p.add_argument("--codex-home", type=Path,
                   help="Codex settings folder (default: $CODEX_HOME, else <home>/.codex)")
    a = p.parse_args(argv)
    home = (a.home or Path.home()).absolute()
    codex_home = a.codex_home or (Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") and not a.home
                                  else None)
    try:
        result = plan(a.profile, home=home, codex_home=codex_home.absolute() if codex_home else None,
                      remove=a.remove)
        if a.apply:
            apply(result)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, (ValueError, TypeError)) else type(exc).__name__
        print("Native merge refused: " + reason, file=sys.stderr)
        return 2
    for change in result["changes"].values():
        change.pop("text")
    result["applied"] = bool(a.apply)
    if not a.apply:
        result["next"] = "re-run with --apply to write these changes"
    elif result["vendor"] == "claude":
        result["next"] = "restart Claude Code, approve the MCP server, then check /hooks, /mcp and integrity-doctor"
    else:
        result["next"] = "restart Codex, trust the hook definitions, then check integrity-doctor"
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
