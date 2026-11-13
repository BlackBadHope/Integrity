# SPDX-License-Identifier: BUSL-1.1
"""Prepare an unapplied LAB discovery candidate; no imports of the reader/RPC.

This is a source artifact, not a ready or activated Native profile. It preserves
the installed runtime and cannot establish ownership or a cloud data boundary.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from guard import checked, install
install()
import ast
import difflib
import hashlib
import json
import re
from types import SimpleNamespace

SOURCE = "runtime/integrity-next-source/components/integrity-client-memory/src/integrity_client_memory/resources/windows/native/delegation-native-reader.py"
TARGET = "controller/native-compatibility-candidate"


def build():
    source = checked(SOURCE).read_text(encoding="utf-8")
    if source.count("codex-browser-use-[A-Za-z0-9-]+") != 2:
        raise AssertionError("upstream discovery source changed; review new preimage")
    old = '''    candidates.extend(
        _read_process_environment_value(process_id, CODEX_APP_TOOLS_PIPE_ENV)
        for process_id in _codex_process_ids()
    )
'''
    if source.count(old) != 1:
        raise AssertionError("unexpected process-environment discovery preimage")
    candidate = source.replace(old, "    # LAB candidate: namespace discovery only; no foreign process-environment reads.\n")
    candidate = candidate.replace("codex-browser-use-[A-Za-z0-9-]+", "codex-(?:app-tools|browser-use)-[A-Za-z0-9-]+")
    candidate = candidate.replace(
        'return [f"\\\\\\\\.\\\\pipe\\\\{name}" for name in names if pattern.fullmatch(name)][:128]',
        'return [f"\\\\\\\\.\\\\pipe\\\\{name}" for name in sorted(names, key=lambda x: (not x.startswith("codex-app-tools-"), x)) if pattern.fullmatch(name)][:128]')
    tree = ast.parse(candidate)
    functions = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name in {
        "discover_codex_app_tool_pipes", "_enumerate_codex_app_tool_pipes"}]
    if len(functions) != 2:
        raise AssertionError("discovery functions not found")
    # Execute only these two extracted functions with a synthetic pipe namespace.
    # No module import, process enumeration, pipe open, tools/list or tools/call.
    fake = SimpleNamespace(name="nt", environ={}, listdir=lambda path: [
        "codex-browser-use-old", "codex-app-tools-new", "codex-app-tools-new", "other-pipe", "codex-app-tools-bad/name"])
    namespace = {"os": fake, "re": re, "CODEX_APP_TOOLS_PIPE_ENV": "CODEX_APP_TOOLS_PIPE_PATH"}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<synthetic-discovery-only>", "exec"), namespace)
    discover = namespace["discover_codex_app_tool_pipes"]
    expected = [r"\\.\pipe\codex-app-tools-new", r"\\.\pipe\codex-browser-use-old"]
    assert discover() == expected
    fake.environ["INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"] = r"\\.\pipe\codex-app-tools-explicit"
    assert discover()[0] == fake.environ["INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"]
    fake.environ["INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"] = r"\\remote\pipe\codex-app-tools-remote"
    assert discover() == expected
    fake.environ["INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"] = r"\\.\pipe\codex-app-tools-bad/name"
    assert discover() == expected
    fake.name = "posix"
    assert discover() == []
    hashes = {"preimage_sha256": hashlib.sha256(source.encode()).hexdigest(), "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest()}
    out = checked(TARGET)
    out.mkdir(exist_ok=True)
    members = {
        "delegation-native-reader.py": candidate,
        "discovery.patch": "".join(difflib.unified_diff(source.splitlines(True), candidate.splitlines(True),
            fromfile="public-1.9.0/delegation-native-reader.py", tofile="LAB-source-candidate/delegation-native-reader.py")),
        "review.json": json.dumps({"schema": "integrity-lab.native-discovery-candidate.v1",
            "status": "SOURCE_ONLY_NOT_INSTALLED", **hashes, "public_source": SOURCE,
            "changes": ["Accept current app-tools and legacy local pipe names", "Prefer app-tools namespace", "Remove foreign process-environment discovery"],
            "synthetic_tests": ["new_prefix", "legacy_prefix", "deduplication", "explicit_local_override", "reject_remote_UNC", "reject_invalid_suffix", "non_Windows_no_namespace"],
            "execution_scope": "Only two extracted discovery functions against fake os namespace",
            "installed_profiles_changed": False, "live_RPC": "NOT_RUN", "owner_binding": "NOT_RUN",
            "remaining": ["Independent pipe-server PID/image validation before use", "Native profile rebuild and trust review", "Real own-turn lifecycle", "Allowlisted LAB-only cloud tool route; shared-account privacy remains unproven"],
            "warning": "Discovery compatibility is not owner authorization, cloud isolation or Native acceptance. Do not activate this source as a shortcut."}, ensure_ascii=False, indent=2) + "\n"
    }
    for name, data in members.items():
        p = checked(out / name)
        if p.exists() and p.read_text(encoding="utf-8") != data:
            raise FileExistsError("candidate already differs; preserve it for review")
        if not p.exists():
            with p.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(data)
    return {"status": "SOURCE_ONLY_NOT_INSTALLED", **hashes, "synthetic_checks": 7, "model_turns": 0, "installed_profile_changes": 0}


if __name__ == "__main__":
    print(json.dumps(build()))
