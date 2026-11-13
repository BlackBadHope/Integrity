#!/usr/bin/env python3
"""Cross-platform stdlib hook for Integrity admission and Turn Memory coverage."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import queue
import re
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
import types as _compact_types
_compact_admission = _compact_types.ModuleType("integrity_compact_admission")
exec(compile('"""File-backed admission presentation; never change canonical admission or receipts."""\nfrom __future__ import annotations\n\nimport copy\nimport hashlib\nimport json\nimport os\nimport re\nimport stat\nimport tempfile\nfrom pathlib import Path\n\nPROTOCOL = \'integrity-admission-compact/v1\'\nMAX_ARTIFACT = 16 * 1024 * 1024\nMAX_PUBLIC = 8192\nSHA = re.compile(r\'[0-9a-f]{64}\\Z\')\n\n\ndef encode(value):\n    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(\',\', \':\')).encode(\'utf-8\')\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n\n\ndef default_root():\n    # This source revision targets the workstation Codex and Claude clients together.\n    # No public tool argument or environment override can redirect file reads.\n    return Path.home() / \'.codex\' / \'integrity-memory\' / \'admission-artifacts\'\n\n\ndef safe_chain(path):\n    for item in (*reversed(path.parents), path):\n        s = item.lstat()\n        if stat.S_ISLNK(s.st_mode) or getattr(s, \'st_file_attributes\', 0) & 0x400:\n            raise ValueError(\'artifact_link_refused\')\n\n\ndef read_file(root, hexdigest):\n    if not isinstance(hexdigest, str) or not SHA.fullmatch(hexdigest):\n        raise ValueError(\'artifact_digest_invalid\')\n    root = Path(root).absolute()\n    safe_chain(root)\n    path = root / (hexdigest + \'.json\')\n    safe_chain(path)\n    flags = os.O_RDONLY | getattr(os, \'O_BINARY\', 0) | getattr(os, \'O_NOFOLLOW\', 0)\n    fd = os.open(path, flags)\n    with os.fdopen(fd, \'rb\') as stream:\n        before = os.fstat(stream.fileno())\n        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT:\n            raise ValueError(\'artifact_file_invalid\')\n        data = stream.read(MAX_ARTIFACT + 1)\n        after = os.fstat(stream.fileno())\n    if (len(data) > MAX_ARTIFACT or before.st_size != after.st_size\n            or before.st_mtime_ns != after.st_mtime_ns or digest(data) != hexdigest):\n        raise ValueError(\'artifact_digest_mismatch\')\n    return data\n\n\ndef store_file(root, data):\n    if len(data) > MAX_ARTIFACT:\n        raise ValueError(\'artifact_too_large\')\n    root = Path(root).absolute()\n    # Validate existing ancestors before mkdir; validate the complete chain after.\n    existing = root\n    while not existing.exists():\n        existing = existing.parent\n    safe_chain(existing)\n    root.mkdir(parents=True, exist_ok=True, mode=0o700)\n    safe_chain(root)\n    hexdigest = digest(data)\n    path = root / (hexdigest + \'.json\')\n    if path.exists():\n        if read_file(root, hexdigest) != data:\n            raise ValueError(\'artifact_collision\')\n        return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n    fd, temporary_name = tempfile.mkstemp(prefix=\'.admission-\', suffix=\'.tmp\', dir=root)\n    temporary = Path(temporary_name)\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        # Atomic no-clobber publication. A failed/terminated write cannot leave\n        # incomplete bytes under the final digest name. NTFS supports hard links.\n        try:\n            os.link(temporary, path)\n        except FileExistsError:\n            if read_file(root, hexdigest) != data:\n                raise ValueError(\'artifact_collision\')\n    finally:\n        temporary.unlink(missing_ok=True)\n    if read_file(root, hexdigest) != data:\n        raise ValueError(\'artifact_readback_mismatch\')\n    return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n\n\ndef admission_document(result):\n    if not isinstance(result, dict) or result.get(\'isError\') is True:\n        return None\n    content = result.get(\'content\')\n    if not isinstance(content, list) or len(content) != 1:\n        return None\n    block = content[0]\n    if not isinstance(block, dict) or block.get(\'type\') != \'text\':\n        return None\n    try:\n        doc = json.loads(block[\'text\'])\n    except (KeyError, ValueError, TypeError):\n        return None\n    if not isinstance(doc, dict) or doc.get(\'protocol\') not in {\n        \'integrity-client-memory-mcp/v3/context-admission/v1\',\n        \'integrity-client-memory-mcp/v3/context-admission/v2\',\n    }:\n        return None\n    return doc\n\n\ndef resolve_wrapper(wrapper, root=None):\n    if not isinstance(wrapper, dict) or wrapper.get(\'protocol\') != PROTOCOL:\n        return wrapper\n    artifact = wrapper.get(\'full_admission\')\n    if not isinstance(artifact, dict):\n        raise ValueError(\'artifact_reference_missing\')\n    # The path is explanatory only; read only the pinned root + digest name.\n    trusted = default_root() if root is None else Path(root)\n    if artifact.get(\'path\') != str(trusted.absolute() / (str(artifact.get(\'sha256\')) + \'.json\')):\n        raise ValueError(\'artifact_path_mismatch\')\n    raw = read_file(trusted, artifact.get(\'sha256\'))\n    if artifact.get(\'bytes\') != len(raw):\n        raise ValueError(\'artifact_size_mismatch\')\n    result = json.loads(raw)\n    doc = admission_document(result)\n    if doc is None:\n        raise ValueError(\'artifact_not_admission\')\n    if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n        raise ValueError(\'artifact_document_shape_invalid\')\n    binding = wrapper.get(\'admission\')\n    expected = {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\'),\n                \'status\': doc.get(\'status\')}\n    if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in expected.items()):\n        raise ValueError(\'artifact_admission_binding_mismatch\')\n    # The hook still runs its original prompt/snapshot/receipt validation on doc.\n    return doc\n\n\ndef _public_result(wrapper):\n    return {\'content\': [{\'type\': \'text\', \'text\': encode(wrapper).decode(\'utf-8\')}], \'isError\': False}\n\n\ndef public_size(wrapper):\n    return len(encode(_public_result(wrapper)))\n\n\ndef _clip(text, byte_limit):\n    return text.encode(\'utf-8\')[:max(0, byte_limit)].decode(\'utf-8\', errors=\'ignore\')\n\n\nclass Presenter:\n    def __init__(self, root=None):\n        self.root = default_root() if root is None else Path(root)\n        self.capabilities_sha256 = None\n        self.capabilities_by_context = {}\n\n    def present(self, result, *, context_key=None):\n        try:\n            doc = admission_document(result)\n            if doc is None:\n                return result\n            return self._present(result, doc, context_key)\n        except Exception as exc:\n            # Admission may already have succeeded. Do not turn that success into\n            # a retry or hide its identity: retain the original response and mark\n            # presentation degraded. The strict byte bound is explicitly unmet.\n            fault = {\n                \'protocol\': \'integrity-compact-presentation-fault/v1\',\n                \'status\': \'degraded\', \'reason\': type(exc).__name__,\n                \'notify_owner_required\': True, \'byte_budget_met\': False,\n                \'admission_repeated\': False,\n            }\n            # The original admission JSON itself remains byte-identical, so no\n            # top-level field can accidentally enter a signed/digested document.\n            return {**result, \'content\': [{\'type\': \'text\', \'text\': encode(fault).decode(\'utf-8\')},\n                                         *result.get(\'content\', [])]}\n\n    def _present(self, result, doc, context_key):\n        if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n            raise ValueError(\'artifact_document_shape_invalid\')\n        ref = store_file(self.root, encode(result))\n        mind = doc.get(\'mind\', {})\n        capsule = mind.get(\'mind\', {}) if isinstance(mind, dict) else {}\n        if not isinstance(capsule, dict):\n            capsule = {}\n        crc = doc.get(\'canonical_read_context\') or mind.get(\'canonical_read_context\') or {}\n        if not isinstance(crc, dict):\n            crc = {}\n        events = crc.get(\'events\', [])\n        if not isinstance(events, list):\n            events = []\n        ids = crc.get(\'event_ids\') or [e.get(\'event_id\', e.get(\'id\')) for e in events if isinstance(e, dict)]\n        if not isinstance(ids, list):\n            ids = []\n        text = doc.get(\'context_text\') or capsule.get(\'context_text\') or \'\'\n        if not isinstance(text, str):\n            text = \'\'\n        synaptic = capsule.get(\'synaptic\', {})\n        if not isinstance(synaptic, dict):\n            synaptic = {}\n        selection = mind.get(\'selection_receipt\', {})\n        if not isinstance(selection, dict):\n            selection = {}\n        if not text:\n            topic = crc.get(\'topic\') or \'события \' + \', \'.join(str(x) for x in ids)\n            text = \'Тема: \' + str(topic) + \'\\n\' + encode({\n                \'door\': synaptic.get(\'door\'),\n                \'selected_candidates\': selection.get(\'selected_candidates\'),\n                \'canonical_event_ids\': ids,\n            }).decode(\'utf-8\')\n            text += \'\\nSelected: \' + encode(capsule.get(\'working_set\', {})).decode(\'utf-8\')\n            text += \'\\nSynaptic: \' + encode({key: synaptic.get(key)\n                for key in (\'here\', \'links\', \'moves\', \'learned_hints\')}).decode(\'utf-8\')\n        delivery = doc.get(\'context_delivery\') or capsule.get(\'context_delivery\') or {}\n        capabilities = doc.get(\'capabilities\')\n        cap_sha = digest(encode(capabilities))\n        previous = self.capabilities_by_context.get(context_key) if context_key is not None else None\n        cap_change = \'first\' if previous is None else (\n            \'unchanged\' if cap_sha == previous else \'changed\')\n        wrapper = {\n            \'protocol\': PROTOCOL, \'full_admission\': ref,\n            \'context_text\': \'\', \'context_delivery\': delivery,\n            \'admission\': {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                          \'status\': doc.get(\'status\'), \'health\': doc.get(\'health\'),\n                          \'door\': synaptic.get(\'door\'),\n                          \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\')},\n            \'selected\': selection.get(\'selected_candidates\'),\n            \'canonical_read_context\': {\'event_ids\': ids, \'events\': [],\n                \'admission_json_string_in_full_result\': \'/content/0/text\',\n                \'events_pointer_in_parsed_admission\': (\'/canonical_read_context/events\'\n                    if doc.get(\'canonical_read_context\') else \'/mind/canonical_read_context/events\')},\n            \'presentation\': {\'byte_limit\': MAX_PUBLIC, \'status\': \'file-backed\',\n                             \'context_text_truncated\': False, \'deferred_exact_event_ids\': [],\n                             \'deferred_events\': []},\n            \'capabilities_ref\': {\'sha256\': cap_sha, \'status\': cap_change,\n                                 \'cache_scope\': \'verified-thread\' if context_key is not None else \'disabled-unbound\',\n                                 \'json_pointer_in_admission\': \'/capabilities\'},\n        }\n        # Reserve space for an owner-visible topic/context excerpt first.\n        wrapper[\'context_text\'] = _clip(text, 1024)\n        deferred = []\n        for index, event in enumerate(events):\n            trial = copy.deepcopy(wrapper)\n            trial[\'canonical_read_context\'][\'events\'].append(event)\n            # Keep space for diagnostics, deferred IDs, and capabilities summary.\n            if public_size(trial) <= MAX_PUBLIC - 1200:\n                wrapper = trial\n            else:\n                event_id = event.get(\'event_id\', event.get(\'id\')) if isinstance(event, dict) else None\n                if event_id is not None:\n                    deferred.append(event_id)\n                row = {\'index\': index, \'sha256\': digest(encode(event))}\n                if event_id is not None:\n                    row[\'event_id\'] = event_id\n                wrapper[\'presentation\'][\'deferred_events\'].append(row)\n        wrapper[\'presentation\'][\'deferred_exact_event_ids\'] = deferred\n        if cap_change != \'unchanged\':\n            trial = {**wrapper, \'capabilities\': capabilities}\n            if public_size(trial) <= MAX_PUBLIC - 512:\n                wrapper = trial\n            else:\n                wrapper[\'capabilities_ref\'][\'status\'] = cap_change + \'_deferred\'\n        current_text = wrapper[\'context_text\']\n        remaining = MAX_PUBLIC - public_size(wrapper) - 32\n        if remaining > 0 and current_text != text:\n            trial = {**wrapper, \'context_text\': _clip(text, len(current_text.encode(\'utf-8\')) + remaining // 2)}\n            while public_size(trial) > MAX_PUBLIC:\n                trial[\'context_text\'] = _clip(trial[\'context_text\'], len(trial[\'context_text\'].encode(\'utf-8\')) // 2)\n            wrapper = trial\n        wrapper[\'presentation\'][\'context_text_truncated\'] = wrapper[\'context_text\'] != text\n        if public_size(wrapper) > MAX_PUBLIC:\n            raise ValueError(\'compact_metadata_exceeds_byte_budget\')\n        # Commit advertisement state only after successful serialization/storage.\n        if \'capabilities\' in wrapper:\n            self.capabilities_sha256 = cap_sha\n            if context_key is not None:\n                self.capabilities_by_context[context_key] = cap_sha\n        return _public_result(wrapper)\n', "frozen-compact-admission", "exec"), _compact_admission.__dict__)
# ISS-050: resolver for the broker's integrity-append-compact/v1 view.
_compact_view = _compact_types.ModuleType("integrity_compact_view")
exec(compile('"""ISS-050: model-facing compact view of two Integrity tool results (Claude broker on one workstation only).\n\nNothing canonical changes. The full MCP result is stored byte-exact, file-backed by sha256, in the\nsame root the hook\'s existing resolver reads (integrity-admission-compact/v1); the model gets a\nshort view; the hook resolves the full document and runs its unchanged validation on it.\n\n  admission (integrity_context_admission_current_turn / integrity_context_admission):\n      protocol integrity-admission-compact/v1, profile "claude-minimal": admission id/status/health/\n      door/snapshot id (the binding the hook checks), the working set the model acts on (owner rules,\n      memory hits, route hints, invariants, attention, contradictions, moves) and, only when not\n      ready, the delivery reasons. Dropped from the view: capabilities, authority_contract copies,\n      context_delivery copies, selection receipt, architecture, counts. All stay in the artifact.\n  append (integrity_append_event):\n      protocol integrity-append-compact/v1: event_id, event_uid, request_sha256, outcome,\n      automatic_retry_allowed + the artifact reference. Only a created/duplicate append-receipt is\n      compacted; denials and unknown outcomes pass unchanged.\n\nSwitch: file ~\\\\.claude\\\\integrity-memory\\\\compact-presentation.json (SWITCH below),\n{"admission": "minimal", "append": "compact", "until": "2026-01-01T00:00:00Z"}. Absent, unreadable,\nother values, missing/unparseable "until" or "until" in the past = full results exactly as before.\n"until" makes every enablement self-expiring: if the live hook ever refused the short view, the\nsessions would recover by themselves when it lapses, without a tool call (rev. 2, review remark).\nAny failure while compacting returns the original result unchanged (never a retry, never a loss).\n\nRev. 2 (review): coordination lines (STOP / LOCK / CONFLICT / GO / HOSTS) and MOVE go\nfirst, outside the text budget, and are never dropped; CONTRA before INV; clipping by characters\n(RULE/HOW and HIT ~300 characters), working-set budget ~4500 bytes.\n"""\nfrom __future__ import annotations\n\nimport hashlib\nimport json\nimport os\nimport re\nimport stat\nimport tempfile\nfrom pathlib import Path\n\nADMISSION_PROTOCOL = "integrity-admission-compact/v1"\nAPPEND_PROTOCOL = "integrity-append-compact/v1"\nPROFILE = "claude-minimal"\nMAX_ARTIFACT = 16 * 1024 * 1024\nTEXT_BUDGET = 4500           # bytes of budgeted working-set lines (protected lines are extra)\nFIELD_CHARS = 300            # characters per RULE / HOW / HIT / HINT text\nSHORT_CHARS = 200            # characters per ATTN / CONTRA / INV / MOVE / coordination item\nSHA = re.compile(r"[0-9a-f]{64}\\Z")\nSWITCH = Path.home() / ".claude" / "integrity-memory" / "compact-presentation.json"\nADMISSION_PROTOCOLS = {"integrity-client-memory-mcp/v3/context-admission/v1",\n                       "integrity-client-memory-mcp/v3/context-admission/v2"}\n\n\ndef encode(value):\n    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")\n\n\ndef default_root():\n    # Same pinned root as the hook\'s resolver (integrity-admission-compact/v1).\n    return Path.home() / ".codex" / "integrity-memory" / "admission-artifacts"\n\n\ndef _safe_chain(path):\n    for item in (*reversed(path.parents), path):\n        s = item.lstat()\n        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:\n            raise ValueError("artifact_link_refused")\n\n\ndef read_file(root, hexdigest):\n    if not isinstance(hexdigest, str) or not SHA.fullmatch(hexdigest):\n        raise ValueError("artifact_digest_invalid")\n    root = Path(root).absolute()\n    _safe_chain(root)\n    path = root / (hexdigest + ".json")\n    _safe_chain(path)\n    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))\n    with os.fdopen(fd, "rb") as stream:\n        before = os.fstat(stream.fileno())\n        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT:\n            raise ValueError("artifact_file_invalid")\n        data = stream.read(MAX_ARTIFACT + 1)\n        after = os.fstat(stream.fileno())\n    if (len(data) > MAX_ARTIFACT or before.st_size != after.st_size\n            or before.st_mtime_ns != after.st_mtime_ns or hashlib.sha256(data).hexdigest() != hexdigest):\n        raise ValueError("artifact_digest_mismatch")\n    return data\n\n\ndef store_file(root, data):\n    """Same publication rules as the hook-side resolver\'s store: atomic, no-clobber, read back."""\n    if len(data) > MAX_ARTIFACT:\n        raise ValueError("artifact_too_large")\n    root = Path(root).absolute()\n    existing = root\n    while not existing.exists():\n        existing = existing.parent\n    _safe_chain(existing)\n    root.mkdir(parents=True, exist_ok=True, mode=0o700)\n    _safe_chain(root)\n    hexdigest = hashlib.sha256(data).hexdigest()\n    path = root / (hexdigest + ".json")\n    if path.exists():\n        if read_file(root, hexdigest) != data:\n            raise ValueError("artifact_collision")\n        return {"sha256": hexdigest, "bytes": len(data), "path": str(path)}\n    fd, temporary_name = tempfile.mkstemp(prefix=".admission-", suffix=".tmp", dir=root)\n    temporary = Path(temporary_name)\n    try:\n        with os.fdopen(fd, "wb") as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        try:\n            os.link(temporary, path)\n        except FileExistsError:\n            if read_file(root, hexdigest) != data:\n                raise ValueError("artifact_collision")\n    finally:\n        temporary.unlink(missing_ok=True)\n    if read_file(root, hexdigest) != data:\n        raise ValueError("artifact_readback_mismatch")\n    return {"sha256": hexdigest, "bytes": len(data), "path": str(path)}\n\n\nUNTIL_RE = re.compile(r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\Z")\n\n\ndef switch(path=None, now=None):\n    """{\'admission\': bool, \'append\': bool}; any doubt (incl. a missing or past "until") = off."""\n    off = {"admission": False, "append": False}\n    try:\n        import datetime as _dt\n        target = SWITCH if path is None else Path(path)\n        if not target.is_file() or target.is_symlink() or target.stat().st_size > 4096:\n            return off\n        value = json.loads(target.read_text(encoding="utf-8"))\n        until = value.get("until")\n        if not isinstance(until, str) or not UNTIL_RE.fullmatch(until):\n            return off\n        deadline = _dt.datetime.strptime(until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)\n        current = _dt.datetime.now(_dt.timezone.utc) if now is None else now\n        if current >= deadline:\n            return off\n        return {"admission": value.get("admission") == "minimal", "append": value.get("append") == "compact"}\n    except Exception:  # noqa: BLE001 - the switch fails closed to the full result\n        return off\n\n\ndef _single_text_document(result):\n    if not isinstance(result, dict) or result.get("isError") is True:\n        return None\n    content = result.get("content")\n    if not isinstance(content, list) or len(content) != 1:\n        return None\n    block = content[0]\n    if not isinstance(block, dict) or block.get("type") != "text":\n        return None\n    try:\n        doc = json.loads(block["text"])\n    except (KeyError, ValueError, TypeError):\n        return None\n    return doc if isinstance(doc, dict) else None\n\n\ndef _clip(text, limit):\n    """Clip by characters, not bytes (Cyrillic is 2 bytes per letter in UTF-8)."""\n    text = " ".join(str(text).split())\n    return text[:limit] + ("…" if len(text) > limit else "")\n\n\ndef _public(view):\n    return {"content": [{"type": "text", "text": encode(view).decode("utf-8")}], "isError": False}\n\n\ndef _item(value):\n    return value if isinstance(value, str) else encode(value).decode("utf-8")\n\n\ndef coordination_lines(doc):\n    """STOP / LOCK / CONFLICT / GO / HOSTS from the capsule\'s coordination summary and the mind\n    admission receipt. The coordination-first rule depends on them: never budgeted."""\n    mind = doc.get("mind") or {}\n    capsule = mind.get("mind") or {}\n    coord = capsule.get("coordination_summary") or {}\n    receipt = mind.get("admission_receipt") or {}\n    lines = []\n    if coord.get("stop_required") is True or receipt.get("coordination_stop_required") is True:\n        lines.append("STOP coordination stop required: do not start writes; resolve the lock/conflict first")\n    for lock in coord.get("active_locks") or []:\n        lines.append("LOCK " + _clip(_item(lock), SHORT_CHARS))\n    for conflict in coord.get("task_conflicts") or []:\n        lines.append("CONFLICT " + _clip(_item(conflict), SHORT_CHARS))\n    if coord.get("owner_go_required") is True:\n        lines.append("GO owner GO required for this scope")\n    hosts = coord.get("affected_hosts") or []\n    if hosts:\n        lines.append("HOSTS " + _clip(", ".join(_item(h) for h in hosts), SHORT_CHARS))\n    return lines\n\n\ndef working_set_text(doc):\n    """The part of the admission the model acts on, as compact lines (no hashes, no counts).\n\n    Protected (outside the budget, never dropped): coordination lines, then MOVE.\n    Budgeted, in this order: RULE, HIT, HINT, ATTN, CONTRA, INV (the tail is dropped first).\n    """\n    capsule = (doc.get("mind") or {}).get("mind") or {}\n    ws = capsule.get("working_set") or {}\n    syn = capsule.get("synaptic") or {}\n    protected = coordination_lines(doc)\n    for move in syn.get("moves") or []:\n        if isinstance(move, dict):\n            protected.append("MOVE " + _clip(f"{move.get(\'kind\')}: {move.get(\'reason\')}", SHORT_CHARS))\n    lines = []\n    for rule in ws.get("owner_rules") or []:\n        if isinstance(rule, dict):\n            lines.append("RULE " + _clip(rule.get("rule", ""), FIELD_CHARS) + " | HOW " + _clip(rule.get("how", ""), FIELD_CHARS))\n    for hit in ws.get("recall_hits") or []:\n        if isinstance(hit, dict):\n            lines.append(f"HIT #{hit.get(\'id\')} " + _clip(hit.get("summary", ""), FIELD_CHARS))\n    for hint in syn.get("learned_hints") or []:\n        lines.append("HINT " + _clip(hint, FIELD_CHARS))\n    for item in ws.get("attention_items") or []:\n        if isinstance(item, dict):\n            lines.append("ATTN " + _clip(item.get("summary", ""), SHORT_CHARS) + " -> " + _clip(item.get("next_action", ""), SHORT_CHARS))\n    for item in ws.get("contradictions") or []:\n        lines.append("CONTRA " + _clip(_item(item), SHORT_CHARS))\n    for item in ws.get("invariants") or []:\n        lines.append("INV " + _clip(item, SHORT_CHARS))\n    out, used, dropped = [], 0, 0\n    for line in lines:\n        size = len(line.encode("utf-8")) + 1\n        if used + size > TEXT_BUDGET:\n            dropped += 1\n            continue\n        out.append(line)\n        used += size\n    return "\\n".join(protected + out), dropped\n\n\ndef present_admission(result, root=None, enabled=None):\n    try:\n        if not (switch()["admission"] if enabled is None else enabled):\n            return result\n        doc = _single_text_document(result)\n        if doc is None or doc.get("protocol") not in ADMISSION_PROTOCOLS:\n            return result\n        if not isinstance(doc.get("snapshot"), dict) or not isinstance(doc.get("mind"), dict):\n            return result\n        ref = store_file(default_root() if root is None else root, encode(result))\n        capsule = doc["mind"].get("mind") or {}\n        syn = capsule.get("synaptic") or {}\n        text, dropped = working_set_text(doc)\n        delivery = doc.get("context_delivery") or {}\n        view = {\n            "protocol": ADMISSION_PROTOCOL,\n            "full_admission": ref,\n            "admission": {"context_admission_id": doc.get("context_admission_id"),\n                          "status": doc.get("status"), "health": doc.get("health"),\n                          "door": syn.get("door"),\n                          "snapshot_id": doc["snapshot"].get("snapshot_id")},\n            "context_text": text,\n            "presentation": {"profile": PROFILE, "status": "file-backed",\n                             "working_set_lines_dropped": dropped,\n                             "full_bytes": ref["bytes"]},\n        }\n        if delivery.get("status") != "ready" or doc.get("status") != "ready":\n            view["not_ready"] = {key: delivery.get(key) for key in\n                                 ("status", "read_plane", "reasons", "evidence_issues", "notify_owner_required")}\n        crc = doc.get("canonical_read_context") or doc["mind"].get("canonical_read_context") or {}\n        if isinstance(crc, dict) and crc.get("event_ids"):\n            view["canonical_event_ids"] = crc.get("event_ids")\n        return _public(view)\n    except Exception:  # noqa: BLE001 - the admission already happened; never hide or repeat it\n        return result\n\n\ndef _append_receipt(doc):\n    receipt = doc.get("receipt") if isinstance(doc, dict) else None\n    if not isinstance(receipt, dict) or not str(receipt.get("protocol", "")).endswith("/append-receipt"):\n        return None\n    return receipt\n\n\ndef present_append(result, root=None, enabled=None):\n    try:\n        if not (switch()["append"] if enabled is None else enabled):\n            return result\n        doc = _single_text_document(result)\n        receipt = _append_receipt(doc)\n        if receipt is None or receipt.get("outcome") not in {"created", "duplicate"}:\n            return result\n        ref = store_file(default_root() if root is None else root, encode(result))\n        view = {"protocol": APPEND_PROTOCOL, "full_receipt": ref,\n                "receipt": {key: receipt.get(key) for key in\n                            ("event_id", "event_uid", "request_sha256", "outcome", "automatic_retry_allowed")}}\n        return _public(view)\n    except Exception:  # noqa: BLE001\n        return result\n\n\ndef resolve_append(wrapper, root=None):\n    """Hook side: the full append-receipt document behind an integrity-append-compact/v1 view."""\n    if not isinstance(wrapper, dict) or wrapper.get("protocol") != APPEND_PROTOCOL:\n        return wrapper\n    artifact = wrapper.get("full_receipt")\n    if not isinstance(artifact, dict):\n        raise ValueError("artifact_reference_missing")\n    trusted = default_root() if root is None else Path(root)\n    if artifact.get("path") != str(trusted.absolute() / (str(artifact.get("sha256")) + ".json")):\n        raise ValueError("artifact_path_mismatch")\n    raw = read_file(trusted, artifact.get("sha256"))\n    if artifact.get("bytes") != len(raw):\n        raise ValueError("artifact_size_mismatch")\n    doc = _single_text_document(json.loads(raw))\n    receipt = _append_receipt(doc)\n    if receipt is None:\n        raise ValueError("artifact_not_append_receipt")\n    binding = wrapper.get("receipt")\n    if not isinstance(binding, dict) or any(\n            binding.get(key) != receipt.get(key) for key in ("event_id", "event_uid", "request_sha256", "outcome")):\n        raise ValueError("artifact_append_binding_mismatch")\n    return doc\n', "frozen-compact-view-iss050", "exec"), _compact_view.__dict__)
from typing import Any

import integrity_client_turn_envelope as turn_envelope

try:
    # Turn-close guard, integrity-next v7.0.0-beta.3 (client-memory 1.11.0), vendored beside this hook.
    import integrity_turn_guard as _turn_guard
except Exception:  # noqa: BLE001 - a missing guard must never break the lifecycle hook
    _turn_guard = None

EXPECTED_TOOLS = [
    "integrity_read_events",
    "integrity_append_event",
    "integrity_turn_memory_open",
    "integrity_turn_memory_close",
    "integrity_turn_memory_gap",
    "integrity_turn_memory_coverage",
    "integrity_home_search",
    "integrity_home_fetch",
    "integrity_context_admission",
    "integrity_context_admission_current_turn",
    "integrity_memory_capabilities",
    "integrity_seed_snapshot",
    "integrity_mind_graph",
    "integrity_architecture_admission",
    "integrity_seed_tasks",
    "integrity_seed_event_uid",
    "integrity_seed_connections",
    "integrity_memory_entity_brief",
    "integrity_memory_link_audit",
    "integrity_seed_replay",
]
DIRECT_CURRENT_EXPECTED_TOOLS = [
    name for name in EXPECTED_TOOLS if name != "integrity_context_admission_current_turn"
]
PREVIOUS_EXPECTED_TOOLS = [
    name
    for name in DIRECT_CURRENT_EXPECTED_TOOLS
    if name != "integrity_seed_event_uid"
]
LEGACY_EXPECTED_TOOLS = [
    name
    for name in PREVIOUS_EXPECTED_TOOLS
    if name not in {"integrity_memory_entity_brief", "integrity_memory_link_audit"}
]
# A broker serves exactly its installed tools contract. The hook reads that same
# contract instead of keeping its own copy, so the two can never drift apart.
# The core below must always be present for turn registration and closure.
REQUIRED_BROKER_CORE_TOOLS = frozenset(
    {
        "integrity_append_event",
        "integrity_turn_memory_open",
        "integrity_turn_memory_close",
        "integrity_turn_memory_gap",
        "integrity_turn_memory_coverage",
        "integrity_context_admission",
        "integrity_context_admission_current_turn",
        "integrity_memory_capabilities",
        "integrity_seed_snapshot",
    }
)
TOOLS_CONTRACT_ARGUMENT = "--tools-contract"
TOOLS_CONTRACT_MAX_BYTES = 4 * 1024 * 1024
TOOL_NAME_RE = re.compile(r"^integrity_[a-z0-9_]{1,80}$")
HEALTH_FILE = "hook-health.json"
# Offline notice: a model session whose MCP server never started
# used to see READ PLANE PENDING forever. Advisory only; never blocks a turn.
BROKER_HEALTH_FILE = "broker-health.json"
OFFLINE_STREAK_THRESHOLD = 2
# Claude Code transcript provenance of prompts that no owner typed.
NON_OWNER_PROMPT_ORIGINS = frozenset({("task_notification", "system"), ("peer", "cross-session")})
# Claude Desktop records relayed session messages and side-session events as ('sdk', 'sdk');
# only their leading harness tag (after system reminders) tells them apart from owner text.
HARNESS_PROMPT_TAG_RE = re.compile(
    r"\A(?:\s*<system-reminder>.*?</system-reminder>)*\s*"
    r"(?:<(?:cross-session-message|side-sessions-event|task-notification)[\s>]"
    # Claude Desktop 2.1.3xx relays background-task and peer-idle events as plain
    # text banners (owner rule: no admission on such turns).
    r"|\[SYSTEM NOTIFICATION - NOT USER INPUT\]"
    r"|\[Cross-session (?:idle|delivery) notice\])",
    re.DOTALL,
)
# The MCP server name users see in /mcp.
MCP_SERVER_LABEL = "integrity-local-memory"
TRANSCRIPT_TAIL_BYTES = 256 * 1024
PREVIOUS_PROMPT_TAIL_BYTES = 4 * 1024 * 1024
PREVIOUS_PROMPT_WINDOW_SECONDS = 60
BACKGROUND_ADMISSIONS_KEPT = 8
NOTIFICATION_TURN_KIND = "harness-notification-probable"
ATTACHMENT_ONLY_PROMPT = "[owner message without text: attachments only]"
SERVER_NAME = "integrity-client-memory"
BROKER_SERVER_VERSION = "1.6.0"
BROKER_COMPATIBLE_VERSIONS = frozenset({BROKER_SERVER_VERSION, "1.4.1", "1.4.0"})
SERVER_VERSION = "2.10.0"
PREVIOUS_SERVER_VERSION = "2.9.0"
OLDER_SERVER_VERSION = "2.8.0"
LEGACY_SERVER_VERSION = "2.7.0"
ROLLOUT_LEGACY_SERVER_VERSION = "2.6.0"
HOOK_VERSION = "1.7.5"
# ISS-013: the broker drops a silent upstream after UPSTREAM_INITIALIZE_TIMEOUT_SECONDS=20
# and reconnects once; the server then answers (gap observed twice) while the hook
# had already given up at 35 s. 48 s per read inside a 52 s budget waits for that one retry and,
# with up to 5 s for broker close, stays under the 60 s hook timeout.
LIFECYCLE_BUDGET_SECONDS = 52
LIFECYCLE_DEADLINE: float | None = None
SEMANTIC_CADENCE_MAX_AGE_SECONDS = 3600
SEMANTIC_CADENCE_MAX_ACTIONS = 24
SEMANTIC_CADENCE_MIN_TIMED_ACTIONS = 3
INTEGRITY_TOOL_RE = re.compile(r"(?i)(?:^|__)integrity_[a-z0-9_]+$")
APPEND_TOOL_RE = re.compile(r"(?i)integrity_append_event$")
CONTEXT_TOOL_RE = re.compile(
    r"(?i)integrity_context_admission(?:_current_turn)?$"
)
CURRENT_CONTEXT_TOOL_RE = re.compile(r"(?i)integrity_context_admission_current_turn$")
EVENT_UID_RE = re.compile(r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
MEANINGFUL_TOOL_RE = re.compile(r"(?i)(?:apply_patch|\bEdit\b|\bWrite\b|NotebookEdit)")
# ISS-049: Claude Code sets hook input `agent_id` only inside a subagent (2.1.321 schema:
# "Absent for the main thread, even in --agent sessions"). Strict shape; anything else = parent.
SUBAGENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
MUTATION_TEXT_RE = re.compile(
    r"(?i)\b(?:apply_patch|rm|mv|cp|install|chmod|chown|setfacl|git\s+(?:commit|push)|"
    r"systemctl\s+(?:start|stop|restart|enable|disable)|sed\s+-i|tee)\b"
)


class HookError(RuntimeError):
    pass


class HookTransportError(HookError):
    """A response may be lost; only an idempotent lifecycle call may replay."""


def remaining_lifecycle_seconds(maximum: float) -> float:
    if LIFECYCLE_DEADLINE is None:
        return maximum
    remaining = LIFECYCLE_DEADLINE - time.monotonic()
    if remaining <= 0:
        raise HookError("lifecycle_deadline_exhausted")
    return min(maximum, remaining)


def tool_failure(name: str, result: dict[str, Any]) -> HookError:
    """Keep safe error identity without reflecting arbitrary provider text."""
    document = find_document(result.get("content"), lambda item: "reason" in item)
    reason = str((document or {}).get("reason", ""))
    code = (document or {}).get("reason_code")
    if reason == "turn identity collides with another prompt":
        code = "turn_identity_prompt_collision"
    if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
        code = "provider_denied"
    # Broker lifecycle calls already perform their bounded transport replay.
    return HookError(f"tool_{name}:{code}:reason_sha256={sha256_text(reason)}")


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_object(value: object) -> str:
    return "sha256:" + sha256_text(compact(value))


def _require_exact_keys(value: object, expected: set[str], error: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise HookError(error)
    return value


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def validate_authority_contract(value: object, expected_status: str) -> None:
    contract = _require_exact_keys(
        value,
        {
            "protocol",
            "provider_authority",
            "target_action_authority",
            "coordination",
            "legacy_projection",
        },
        "model_mcp_authority_contract_shape_invalid",
    )
    provider = _require_exact_keys(
        contract.get("provider_authority"),
        {"provider", "scope", "execution", "production", "route", "canonical_seed_append"},
        "model_mcp_provider_authority_shape_invalid",
    )
    target = _require_exact_keys(
        contract.get("target_action_authority"),
        {"decision", "authoritative_source", "provider_boundary_is_target_denial"},
        "model_mcp_target_authority_shape_invalid",
    )
    coordination = _require_exact_keys(
        contract.get("coordination"),
        {
            "scope",
            "status",
            "canonical_seed_append_affected",
            "external_target_actions_affected",
        },
        "model_mcp_coordination_scope_shape_invalid",
    )
    legacy = _require_exact_keys(
        contract.get("legacy_projection"),
        {"production_authority", "semantics", "deprecated", "replacement"},
        "model_mcp_legacy_authority_shape_invalid",
    )
    if (
        contract.get("protocol") != "integrity-guardian/authority-separation/v1"
        or provider
        != {
            "provider": "integrity-client-memory",
            "scope": "canonical-seed-memory",
            "execution": "absent",
            "production": "absent",
            "route": "absent",
            "canonical_seed_append": "one-use-only",
        }
        or target
        != {
            "decision": "not-evaluated",
            "authoritative_source": "target-specific-action-guard",
            "provider_boundary_is_target_denial": False,
        }
        or coordination
        != {
            "scope": "integrity-memory-route",
            "status": expected_status,
            "canonical_seed_append_affected": False,
            "external_target_actions_affected": False,
        }
        or legacy
        != {
            "production_authority": False,
            "semantics": "memory-provider-does-not-grant-production-authority",
            "deprecated": True,
            "replacement": "authority_contract.provider_authority.production",
        }
    ):
        raise HookError("model_mcp_authority_contract_invalid")


def negotiated_context_protocol(context: dict[str, Any], requested_protocol: str) -> str:
    if requested_protocol not in {
        "integrity-client-memory-mcp/v3/context-admission/v1",
        "integrity-client-memory-mcp/v3/context-admission/v2",
    }:
        raise HookError("model_mcp_context_presentation_not_bound")
    capabilities = context.get("capabilities")
    if not isinstance(capabilities, dict):
        raise HookError("model_mcp_capabilities_invalid")
    facade = capabilities.get("facade")
    if not isinstance(facade, dict):
        raise HookError("model_mcp_facade_capabilities_invalid")
    identity = (capabilities.get("contract_version"), facade.get("server_version"))
    if identity == ("1.5.0", ROLLOUT_LEGACY_SERVER_VERSION):
        return "integrity-client-memory-mcp/v3/context-admission/v1"
    if identity not in {
        ("1.6.0", LEGACY_SERVER_VERSION),
        ("1.7.0", OLDER_SERVER_VERSION),
        ("1.8.0", PREVIOUS_SERVER_VERSION),
        ("1.9.0", SERVER_VERSION),
    }:
        raise HookError("model_mcp_contract_identity_invalid")
    session = facade.get("session_admission")
    if not isinstance(session, dict):
        raise HookError("model_mcp_session_capabilities_invalid")
    presentation = _require_exact_keys(
        session.get("context_presentation"),
        {"default_protocol", "supported_protocols", "legacy_fixed_selector"},
        "model_mcp_context_capability_shape_invalid",
    )
    if (
        presentation.get("default_protocol") != "integrity-client-memory-mcp/v3/context-admission/v2"
        or presentation.get("supported_protocols")
        != [
            "integrity-client-memory-mcp/v3/context-admission/v2",
            "integrity-client-memory-mcp/v3/context-admission/v1",
        ]
        or presentation.get("legacy_fixed_selector") != "explicit-limit"
    ):
        raise HookError("model_mcp_context_capability_invalid")
    if identity == ("1.9.0", SERVER_VERSION):
        validate_authority_contract(capabilities.get("authority_contract"), "not-evaluated")
    return requested_protocol


def validate_architecture_presentation(envelope: object, mind_receipt: dict[str, Any]) -> bool:
    if not isinstance(envelope, dict):
        raise HookError("model_mcp_architecture_envelope_invalid")
    protocol = envelope.get("protocol")
    if protocol == "integrity-client-memory-mcp/v3/architecture-unavailable/v1":
        _require_exact_keys(
            envelope,
            {
                "protocol",
                "outcome",
                "failure_layer",
                "reason_digest",
                "canonical_writes",
                "production_authority",
            },
            "model_mcp_architecture_unavailable_shape_invalid",
        )
        if (
            envelope.get("outcome") != "unavailable"
            or envelope.get("failure_layer") != "write-plane-admission"
            or not _is_digest(envelope.get("reason_digest"))
            or isinstance(envelope.get("canonical_writes"), bool)
            or envelope.get("canonical_writes") != 0
            or envelope.get("production_authority") is not False
        ):
            raise HookError("model_mcp_architecture_unavailable_invalid")
        return False
    if protocol != "integrity-client-memory-mcp/v3/architecture-capsule/v1":
        raise HookError("model_mcp_architecture_protocol_invalid")
    _require_exact_keys(
        envelope,
        {
            "protocol",
            "architecture",
            "custody",
            "source_architecture_digest",
            "complete",
            "home_record_count",
            "production_authority",
        },
        "model_mcp_architecture_capsule_shape_invalid",
    )
    if (
        not _is_digest(envelope.get("source_architecture_digest"))
        or envelope.get("complete") is not False
        or isinstance(envelope.get("home_record_count"), bool)
        or envelope.get("home_record_count") != 0
        or envelope.get("production_authority") is not False
    ):
        raise HookError("model_mcp_architecture_capsule_boundary_invalid")
    architecture = _require_exact_keys(
        envelope.get("architecture"),
        {"admission_id", "summary"},
        "model_mcp_architecture_shape_invalid",
    )
    summary_fields = {
        "mind_admission_receipt_id",
        "concept_recovery_digest",
        "coordination_digest",
        "coordination_stop_required",
        "route_disposition",
        "ledger_event_digest",
        "checkpoint_digest",
        "atlas_projection_digest",
        "connectome_compilation_id",
        "synapse_plan_id",
    }
    summary = _require_exact_keys(
        architecture.get("summary"),
        summary_fields,
        "model_mcp_architecture_summary_shape_invalid",
    )
    digest_fields = summary_fields - {"coordination_stop_required", "route_disposition"}
    if not _is_digest(architecture.get("admission_id")) or any(
        not _is_digest(summary.get(field)) for field in digest_fields
    ):
        raise HookError("model_mcp_architecture_digest_invalid")
    stop_required = summary.get("coordination_stop_required")
    if not isinstance(stop_required, bool):
        raise HookError("model_mcp_architecture_stop_invalid")
    if (
        summary.get("mind_admission_receipt_id") != mind_receipt.get("receipt_id")
        or summary.get("concept_recovery_digest") != mind_receipt.get("concept_recovery_digest")
        or summary.get("coordination_digest") != mind_receipt.get("coordination_digest")
        or stop_required != mind_receipt.get("coordination_stop_required")
        or summary.get("route_disposition") != ("stopped" if stop_required else "ready")
    ):
        raise HookError("model_mcp_architecture_mind_binding_invalid")
    custody = _require_exact_keys(
        envelope.get("custody"),
        {
            "receipt_id",
            "architecture_admission_id",
            "mind_admission_receipt_id",
            "write_status",
            "checkpoint",
            "home_record_count",
            "production_authority",
        },
        "model_mcp_architecture_custody_shape_invalid",
    )
    checkpoint = _require_exact_keys(
        custody.get("checkpoint"),
        {"checkpoint_id", "root_digest", "tree_size"},
        "model_mcp_architecture_checkpoint_shape_invalid",
    )
    tree_size = checkpoint.get("tree_size")
    if (
        not _is_digest(custody.get("receipt_id"))
        or custody.get("architecture_admission_id") != architecture.get("admission_id")
        or custody.get("mind_admission_receipt_id") != mind_receipt.get("receipt_id")
        or custody.get("write_status") not in {"recorded", "already-recorded"}
        or isinstance(custody.get("home_record_count"), bool)
        or custody.get("home_record_count") != 0
        or custody.get("production_authority") is not False
        or checkpoint.get("checkpoint_id") != "checkpoint:medor-architecture-custody"
        or not _is_digest(checkpoint.get("root_digest"))
        or isinstance(tree_size, bool)
        or not isinstance(tree_size, int)
        or tree_size < 1
    ):
        raise HookError("model_mcp_architecture_custody_invalid")
    return True


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


# Stop and SubagentStop accept no hookSpecificOutput: Codex rejects it as invalid stop hook
# JSON. systemMessage reaches the operator on both harnesses without re-invoking the model.
TERMINAL_EVENTS = frozenset({"Stop", "SubagentStop"})


def output_context(event: str, context: str) -> None:
    if event in TERMINAL_EVENTS:
        print(compact({"continue": True, "systemMessage": context}))
        return
    print(
        compact(
            {
                "continue": True,
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": context,
                },
            }
        )
    )


def deny(reason: str) -> None:
    print(f"Integrity admission blocked this lifecycle step: {reason}", file=sys.stderr)
    raise SystemExit(2)


def payload_value(payload: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return default


def subagent_id(payload: dict[str, Any]) -> str | None:
    """ISS-049: the subagent marker, or None. Only an explicit, well-formed `agent_id` counts.

    A subagent shares the parent's session_id and therefore its hook state, turn_ref and MCP
    logical context. A parent misread as a subagent would lose the admission-first gate (a hole);
    a subagent misread as the parent only keeps the pre-ISS-049 behaviour. So on any doubt the
    call is the parent's.
    """

    value = payload.get("agent_id")
    if isinstance(value, str) and SUBAGENT_ID_RE.fullmatch(value):
        return value
    return None


def session_id(payload: dict[str, Any]) -> str:
    value = payload_value(payload, "session_id", "thread_id", default="")
    if not isinstance(value, str) or not value.strip():
        raise HookError("missing_session_id")
    return value.strip()


def turn_id(payload: dict[str, Any]) -> str:
    value = payload_value(payload, "turn_id", "turnId", default="")
    return value.strip() if isinstance(value, str) else ""


def prompt(payload: dict[str, Any]) -> str:
    value = payload_value(
        payload,
        "prompt",
        "user_prompt",
        "userPrompt",
        "message",
        "input",
        default=None,
    )
    if not isinstance(value, str):
        raise HookError("missing_user_prompt")
    if len(value.encode("utf-8")) > turn_envelope.MAX_PROMPT_BYTES:
        raise HookError("user_prompt_exceeds_256_kib")
    if not value.strip():
        # An image/attachment-only owner message has no text part. Blocking it
        # (exit 2) would drop the owner's message; bind a fixed marker instead.
        return ATTACHMENT_ONLY_PROMPT
    return value


def prompt_kind(payload: dict[str, Any]) -> str:
    """Documented envelope kind: the attachment marker is never owner text."""
    value = payload_value(payload, "prompt", "user_prompt", "userPrompt", "message", "input", default=None)
    return "attachment-only-no-text" if isinstance(value, str) and not value.strip() else "text"


def machine_id() -> str:
    value = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
    if not value:
        raise HookError("missing_machine_id")
    return f"machine:{value}"


def state_root() -> Path:
    override = os.environ.get("INTEGRITY_CLIENT_STATE_ROOT")
    if override:
        target = Path(override).resolve()
    else:
        root = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).resolve()
        target = root / "integrity-memory" / "state"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink():
        raise HookError("unsafe_state_root")
    try:
        target.chmod(0o700)
    except OSError:
        pass
    return target


def state_path(identity: str) -> Path:
    return state_root() / f"{sha256_text(identity)}.json"


# Option 4 (owner decision): the model's warm broker opens the turn registration right after
# admission. The hook leaves the identity hint the broker needs (the broker only sees the
# hashed thread id) and later accepts the broker's receipt, validated exactly like its own.
def _turn_hint_path(turn_ref_digest: str) -> Path:
    return state_root() / f"turn-hint-{turn_ref_digest.split(':')[-1]}.json"


def _turn_registration_path(turn_ref_digest: str) -> Path:
    return state_root() / f"turn-reg-{turn_ref_digest.split(':')[-1]}.json"


def write_turn_hint(identity: str, state: dict[str, Any]) -> None:
    try:
        digest = state.get("turn_ref_digest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            return
        machine = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
        hint = {"protocol": "integrity-client/claude-turn-hint/v1", "machine_id": f"machine:{machine}",
                "thread_id": identity, "turn_id": state.get("turn_memory_intent_id"),
                "prompt_sha256": state.get("prompt_sha256"), "created_utc": utc_now()}
        path = _turn_hint_path(digest)
        temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps(hint), encoding="utf-8")
        os.replace(temporary, path)
        for old in state_root().glob("turn-hint-*.json"):
            if old != path and time.time() - old.stat().st_mtime > 6 * 3600:
                old.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - advisory: the hook still opens the registration itself
        return


def take_broker_registration(state: dict[str, Any]) -> dict[str, Any] | None:
    digest = state.get("turn_ref_digest")
    if not isinstance(digest, str):
        return None
    path = _turn_registration_path(digest)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    return value if isinstance(value, dict) and isinstance(value.get("receipt"), dict) else None


@contextlib.contextmanager
def session_state_lock(identity: str):
    """Serialize hook state transactions, never the model-owned MCP request."""
    path = state_path(identity)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        name = "Local\\IntegrityClientState-" + sha256_text(str(path.absolute()).lower())
        handle = kernel.CreateMutexW(None, False, name)
        if not handle:
            raise HookError("session_state_lock_unavailable")
        acquired = False
        try:
            acquired = kernel.WaitForSingleObject(handle, 10000) in (0, 0x80)
            if not acquired:
                raise HookError("session_state_lock_timeout")
            yield
        finally:
            if acquired:
                kernel.ReleaseMutex(handle)
            kernel.CloseHandle(handle)
    else:
        import fcntl

        descriptor = os.open(
            path.with_suffix(".lock"),
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        deadline = time.monotonic() + 10
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise HookError("session_state_lock_timeout")
                    time.sleep(0.02)
            yield
        finally:
            os.close(descriptor)


def load_state(identity: str) -> dict[str, Any]:
    path = state_path(identity)
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise HookError("unsafe_state_file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise HookError("invalid_session_state")
    return value


def save_state(identity: str, state: dict[str, Any]) -> None:
    path = state_path(identity)
    state = dict(state)
    state["protocol"] = "integrity-memory/session-state/v1"
    state["session_hash"] = sha256_text(identity)
    temporary = path.with_name(f".state-{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(compact(state) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def broker_contract_tools(arguments: list[str]) -> list[str]:
    """Return the exact tool names of the broker's own installed contract."""

    if arguments.count(TOOLS_CONTRACT_ARGUMENT) != 1:
        raise HookError("tool_contract_unavailable")
    index = arguments.index(TOOLS_CONTRACT_ARGUMENT)
    if index + 1 >= len(arguments):
        raise HookError("tool_contract_unavailable")
    path = Path(arguments[index + 1])
    try:
        if path.is_symlink() or not path.is_file():
            raise HookError("tool_contract_unavailable")
        raw = path.read_bytes()
    except OSError as exc:
        raise HookError("tool_contract_unavailable") from exc
    if len(raw) > TOOLS_CONTRACT_MAX_BYTES:
        raise HookError("tool_contract_invalid")
    try:
        contract = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HookError("tool_contract_invalid") from exc
    if not isinstance(contract, list) or not contract:
        raise HookError("tool_contract_invalid")
    names = []
    for item in contract:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or TOOL_NAME_RE.fullmatch(name) is None:
            raise HookError("tool_contract_invalid")
        names.append(name)
    if len(set(names)) != len(names):
        raise HookError("tool_contract_invalid")
    if not REQUIRED_BROKER_CORE_TOOLS <= set(names):
        raise HookError("tool_contract_core_missing")
    return names


def pinned_generation_contract_tools() -> list[str] | None:
    """Tool names the desktop dispatcher actually serves for its pinned generation.

    The hook transport still names the root contract. For the pinned Claude
    session the dispatcher swaps `--tools-contract` to the generation file,
    which adds `integrity_seed_recall`. Accepting that pinned file keeps the
    check exact without changing the legacy contract.
    """

    root = Path(__file__).resolve().parent
    pointer_path = root / "active-native-profile.json"
    try:
        if pointer_path.is_symlink() or not pointer_path.is_file():
            return None
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        generation = pointer.get("generation_id")
        manifest_sha = pointer.get("manifest_sha256")
        if (
            not isinstance(generation, str)
            or len(generation) != 64
            or not isinstance(manifest_sha, str)
            or len(manifest_sha) != 64
        ):
            return None
        folder = root / "native-generations" / generation
        manifest_path = folder / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        manifest_raw = manifest_path.read_bytes()
        if hashlib.sha256(manifest_raw).hexdigest() != manifest_sha:
            return None
        manifest = json.loads(manifest_raw.decode("utf-8"))
        files = manifest.get("files")
        pin = files.get("integrity-client-tools.json") if isinstance(files, dict) else None
        tools_path = folder / "integrity-client-tools.json"
        if (
            manifest.get("generation_id") != generation
            or not isinstance(pin, str)
            or tools_path.is_symlink()
            or not tools_path.is_file()
            or hashlib.sha256(tools_path.read_bytes()).hexdigest() != pin
        ):
            return None
        return broker_contract_tools([TOOLS_CONTRACT_ARGUMENT, str(tools_path)])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, HookError):
        return None


def record_hook_health(operation: str, error: BaseException | None) -> None:
    """Keep one machine-visible record of lifecycle success and failure.

    A failing registration used to be visible only to the model, which could
    carry on without memory. SessionStart reports this record loudly.
    """

    try:
        path = state_root().parent / HEALTH_FILE
        health: dict[str, Any] = {}
        if path.is_file() and not path.is_symlink():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            health = loaded if isinstance(loaded, dict) else {}
        now = utc_now()
        health.update(
            {
                "protocol": "integrity-memory/hook-health/v1",
                "hook_version": HOOK_VERSION,
                "last_operation": operation,
            }
        )
        if error is None:
            health["last_success_utc"] = now
            health["consecutive_failures"] = 0
        else:
            previous = health.get("consecutive_failures")
            health["consecutive_failures"] = (
                previous + 1 if isinstance(previous, int) and previous >= 0 else 1
            )
            health["last_failure_utc"] = now
            health["last_failure"] = f"{type(error).__name__}: {str(error)[:200]}"
        temporary = path.with_name(f".health-{uuid.uuid4().hex}.tmp")
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(compact(health) + "\n")
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except Exception:  # noqa: BLE001 - health is advisory and never blocks a turn
        return


def health_path() -> Path:
    """Locate the health record without creating any state at SessionStart."""

    root = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).resolve()
    return root / "integrity-memory" / HEALTH_FILE


def degraded_health_notice() -> str | None:
    try:
        path = health_path()
        if not path.is_file() or path.is_symlink():
            return None
        health = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    failures = health.get("consecutive_failures") if isinstance(health, dict) else None
    if not isinstance(failures, int) or failures < 1:
        return None
    return (
        "INTEGRITY LIFECYCLE HISTORY: the last "
        f"{failures} memory lifecycle call(s) failed since {health.get('last_failure_utc')} "
        f"({health.get('last_failure')}). This is the last recorded lifecycle failure, "
        "not a current-turn probe. Current read, delivery and registration status are unverified "
        "until this turn's admission and signed lifecycle receipts. Preserve the history; "
        "report a current failure only when current evidence confirms it."
    )


def last_broker_failure() -> str | None:
    """Latest startup failure recorded by the Claude MCP broker shim, if any."""

    try:
        path = Path(__file__).resolve().with_name(BROKER_HEALTH_FILE)
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
            return None
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("status") == "started":
            return None
        return f"at {str(record.get('utc'))[:32]}: {str(record.get('error'))[:200]}"
    except Exception:  # noqa: BLE001
        return None


def probe_memory_server(timeout: float = 50.0) -> tuple[bool, str]:
    """Hook-side probe with upstream evidence: one read-only coverage call.

    A local turn broker answers initialize and tools/list by itself and opens
    its upstream lazily, so a handshake alone would not show memory is reachable.
    ``timeout`` must cover a cold broker start (31-38 s measured over SSH).
    """

    global LIFECYCLE_DEADLINE
    previous = LIFECYCLE_DEADLINE
    LIFECYCLE_DEADLINE = time.monotonic() + timeout
    client = None
    try:
        client = McpClient()
        client.call("integrity_turn_memory_coverage", {"limit": 1})
        return True, "read-only coverage call answered"
    except Exception as exc:  # noqa: BLE001 - the probe reports, never raises
        return False, f"{type(exc).__name__}: {str(exc)[:160]}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        LIFECYCLE_DEADLINE = previous


def read_hook_health() -> dict[str, Any] | None:
    """This hook's own lifecycle health record (hook-health.json), if any."""

    try:
        path = state_root().parent / HEALTH_FILE
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16384:
            return None
        record = json.loads(path.read_text(encoding="utf-8"))
        return record if isinstance(record, dict) else None
    except Exception:  # noqa: BLE001
        return None


def close_interrupted_with_events(registration: str, state: dict[str, Any] | None) -> str | None:
    """ISS-007: an interrupted turn that already appended its event is closed honestly.

    The hook recorded the passive-witness receipt of the one append this turn made
    (created/duplicate). Closing with exactly that event is a fact, not an inferred
    no-event; any failure falls back to the existing gap path. Turns without an
    appended event keep the gap (coverage debt) exactly as before.
    """

    if not isinstance(state, dict) or state.get("append_outcome") not in {"created", "duplicate"}:
        return None
    event_id, event_uid, request = (
        state.get("append_event_id"), state.get("append_event_uid"), state.get("append_request_sha256")
    )
    if (
        isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1
        or not isinstance(event_uid, str) or not isinstance(request, str) or len(request) != 64
    ):
        return None
    try:
        lifecycle_call(
            "integrity_turn_memory_close",
            {
                "registration_id": registration,
                "outcome": "events",
                "events": [{"event_uid": event_uid, "event_id": event_id, "request_sha256": request}],
            },
        )
    except Exception:  # noqa: BLE001 - fall back to the gap path
        return None
    return (
        f"TURN MEMORY INTERRUPTED: the previous turn's registration {registration} was cut off before "
        f"Stop and has been closed with its appended event {event_id} (outcome=events). "
        "Work continued in this turn still needs its own admission and close."
    )


ISS028_GAPPED_CLOSE_BUDGET_SECONDS = 30


def close_gapped_with_events(state: dict[str, Any], close_arguments: Any, identity: str | None = None) -> None:
    """ISS-025: close earlier interrupted, gapped registrations of this session.

    A registration cut off by a new prompt before it appended anything gets a signed gap
    and then stayed open forever. When the session's next turn closes with events, the
    same events close those registrations too: the gap receipt stays as the record of the
    interruption, and the coverage debt is settled by a fact, never by an inferred no-event.
    Failures keep the registration for the next close (two attempts at most).
    """

    pending = [r for r in (state.get("iss025_gapped_registrations") or []) if isinstance(r, str)]
    if not pending or not isinstance(close_arguments, dict):
        return
    events = close_arguments.get("events")
    if not isinstance(events, list) or not events or not all(isinstance(item, dict) for item in events):
        return
    # ISS-028: one registration per hook call, inside a bounded budget, with the
    # attempt persisted before the network call. Two pending closes at up to 52 s each had
    # outlived the 60 s PostToolUse timeout; the killed hook then lost the observed close.
    global LIFECYCLE_DEADLINE
    current = state.get("turn_memory_registration_id")
    candidates = [r for r in pending if r != current]
    if not candidates:
        state["iss025_gapped_registrations"] = []
        state["iss025_close_attempts"] = {}
        return
    registration = candidates[0]
    attempts = dict(state.get("iss025_close_attempts") or {})
    if int(attempts.get(registration, 0)) >= 2:
        # Two attempts were already spent (possibly by killed hooks): give up on it.
        state["iss025_gapped_registrations"] = candidates[1:]
        state["iss025_close_attempts"] = {k: v for k, v in attempts.items() if k in candidates[1:]}
        return
    count = int(attempts.get(registration, 0)) + 1
    attempts[registration] = count
    state["iss025_close_attempts"] = attempts
    if identity is not None:
        save_state(identity, state)
    previous = LIFECYCLE_DEADLINE
    LIFECYCLE_DEADLINE = time.monotonic() + ISS028_GAPPED_CLOSE_BUDGET_SECONDS
    try:
        lifecycle_call(
            "integrity_turn_memory_close",
            {"registration_id": registration, "outcome": "events", "events": events},
        )
        closed = True
    except Exception:  # noqa: BLE001 - advisory; keep it for the next close
        closed = False
    finally:
        LIFECYCLE_DEADLINE = previous
    remaining = [r for r in candidates if r != registration or (not closed and count < 2)]
    state["iss025_gapped_registrations"] = remaining
    state["iss025_close_attempts"] = {k: v for k, v in attempts.items() if k in remaining}


def record_interrupted_gap(interrupted: dict[str, Any] | None, state: dict[str, Any] | None = None) -> str | None:
    """Record coverage debt for a registration a new prompt cuts off before Stop.

    Without this the registration was dropped from hook state while still open:
    no close, no gap, invisible until a manual reconciliation.
    """

    registration = (interrupted or {}).get("registration_id")
    if not isinstance(registration, str):
        return None
    closed = close_interrupted_with_events(registration, state)
    if closed is not None:
        # ISS-023: the cut-off turn's state change is covered by the event it was
        # just closed with. The continuation turn stays an owner turn (still gated), but it
        # must not inherit that change, or Stop demands a second close for covered work.
        if isinstance(interrupted, dict):
            interrupted["state_changed"] = False
        return closed
    try:
        coverage = lifecycle_call(
            "integrity_turn_memory_gap", {"registration_id": registration, "stage": "reconciliation"}
        )
    except Exception as exc:  # noqa: BLE001 - advisory; the prompt must still get its turn_ref
        return (
            f"TURN MEMORY INTERRUPTED: the previous turn's registration {registration} was still open "
            f"when this prompt arrived, and recording its gap failed ({type(exc).__name__}). "
            "Do not claim it is covered."
        )
    gap = coverage.get("receipt", {}) if isinstance(coverage, dict) else {}
    terminal = coverage.get("terminal_receipt") if isinstance(coverage, dict) else None
    if isinstance(terminal, dict):
        return None  # it was closed after all
    if isinstance(state, dict):
        # ISS-025: keep the gapped registration; the session's next close with
        # events closes it too (the owner's work continued), instead of leaving it open forever.
        pending = [r for r in (state.get("iss025_gapped_registrations") or []) if isinstance(r, str)]
        if registration not in pending:
            pending.append(registration)
        state["iss025_gapped_registrations"] = pending[-8:]
    return (
        f"TURN MEMORY INTERRUPTED: this prompt arrived before the previous turn stopped; its open "
        f"registration {registration} was recorded as coverage debt (gap_receipt_id="
        f"{gap.get('receipt_id')}). Work continued in this turn still needs its own admission and close."
    )


def admission_offline_notice(state: dict[str, Any], current_notification: bool = False) -> str | None:
    """Explain a run of turns without admission from evidence, not a guess.

    The previous turn's state is inspected before it is reset. When the
    server answered in this session (a model tool call, the hook's own
    lifecycle call or the hook probe), the notice says the call was skipped.
    The server is called unreachable only when the broker start failed or a
    probe made now was refused twice; a timeout is inconclusive, and a cached
    failure is never shown again. Notification turns get no notice and no probe.
    """

    try:
        if _turn_guard is None:
            return None
        streak = _turn_guard.unattempted_streak(state)
        if streak < OFFLINE_STREAK_THRESHOLD:
            return None
        if current_notification or state.get("turn_kind") == NOTIFICATION_TURN_KIND:
            # A harness notification proves nothing about the connection either way.
            return None
        failure = last_broker_failure()
        lifecycle_ok = _turn_guard.lifecycle_evidence(read_hook_health())
        fresh = False
        if (
            not failure
            and not lifecycle_ok
            and not state.get("mcp_answered_utc")
            and _turn_guard.probe_due(state)
        ):
            ok, detail, failures, conclusive = _turn_guard.run_probe(probe_memory_server)
            _turn_guard.record_probe(state, ok, detail, failures=failures, conclusive=conclusive)
            fresh = True
        return _turn_guard.memory_status_notice(
            state,
            streak,
            server_name=MCP_SERVER_LABEL,
            broker_failure=failure,
            fresh_probe=fresh,
            lifecycle_ok_utc=lifecycle_ok,
        )
    except Exception:  # noqa: BLE001 - advisory only
        return None


def registered_transport() -> dict[str, Any]:
    """The client MCP registration: an installer-written file for Claude Code, Codex's own registry otherwise."""
    explicit = os.environ.get("INTEGRITY_CLIENT_MCP_TRANSPORT")
    if explicit:
        try:
            return json.loads(Path(explicit).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HookError("mcp_registration_unavailable") from exc
    completed = subprocess.run(
        ["codex", "mcp", "get", "integrity_client_memory", "--json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=remaining_lifecycle_seconds(15),
    )
    if completed.returncode != 0:
        raise HookError("mcp_registration_unavailable")
    return json.loads(completed.stdout)


class McpClient:
    def __init__(self) -> None:
        entry = registered_transport()
        transport = entry.get("transport")
        if not isinstance(transport, dict) or transport.get("type") != "stdio":
            raise HookError("transport_type_mismatch")
        command = transport.get("command")
        arguments = transport.get("args", [])
        environment = transport.get("env") or {}
        if (
            not isinstance(command, str)
            or not isinstance(arguments, list)
            or not all(isinstance(item, str) for item in arguments)
            or not isinstance(environment, dict)
        ):
            raise HookError("invalid_mcp_transport")
        self.broker_contract_arguments = list(arguments)
        child_environment = dict(os.environ)
        child_environment.update({str(key): str(value) for key, value in environment.items()})
        self.process = subprocess.Popen(
            [command, *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=child_environment,
            cwd=transport.get("cwd") or None,
        )
        self.next_id = 1
        # On Windows select() accepts only sockets ([WinError 10038] on a pipe), so a reader
        # thread moves stdout lines into a queue and request() waits on the queue instead.
        self._lines: queue.Queue[str] | None = None
        if os.name == "nt" and self.process.stdout is not None:
            self._lines = queue.Queue()
            threading.Thread(target=self._pump_stdout, daemon=True).start()
        try:
            self._initialize_transport()
        except Exception:
            self.close()
            raise

    def _initialize_transport(self) -> None:
        initialized = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "integrity-client-linux-hook", "version": HOOK_VERSION},
            },
        )
        server = initialized.get("serverInfo")
        if (
            not isinstance(server, dict)
            or server.get("name") != SERVER_NAME
            or server.get("version")
            not in {
                *BROKER_COMPATIBLE_VERSIONS,
                ROLLOUT_LEGACY_SERVER_VERSION,
                LEGACY_SERVER_VERSION,
                OLDER_SERVER_VERSION,
                PREVIOUS_SERVER_VERSION,
                SERVER_VERSION,
            }
            or set(server) != {"name", "version"}
        ):
            raise HookError("server_identity_mismatch")
        self.notify("notifications/initialized", {})
        listed = self.request("tools/list", {})
        tools = listed.get("tools")
        server_version = server.get("version")
        expected_tools = (
            broker_contract_tools(self.broker_contract_arguments)
            if server_version in BROKER_COMPATIBLE_VERSIONS
            else LEGACY_EXPECTED_TOOLS
            if server_version in {ROLLOUT_LEGACY_SERVER_VERSION, LEGACY_SERVER_VERSION}
            else PREVIOUS_EXPECTED_TOOLS
            if server_version == OLDER_SERVER_VERSION
            else DIRECT_CURRENT_EXPECTED_TOOLS
        )
        served_names = [item.get("name") for item in tools] if isinstance(tools, list) else None
        allowed_contracts = [expected_tools]
        if server_version in BROKER_COMPATIBLE_VERSIONS:
            pinned_names = pinned_generation_contract_tools()
            if pinned_names is not None and pinned_names not in allowed_contracts:
                allowed_contracts.append(pinned_names)
        if served_names not in allowed_contracts:
            raise HookError("tool_contract_mismatch")

    def _pump_stdout(self) -> None:
        assert self._lines is not None
        try:
            for line in self.process.stdout:
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put("")

    def _readline(self, timeout: float) -> str:
        if self._lines is not None:
            try:
                return self._lines.get(timeout=max(timeout, 0))
            except queue.Empty as exc:
                raise HookTransportError("response_timeout") from exc
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            raise HookTransportError("response_timeout")
        return self.process.stdout.readline()

    def _send(self, value: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise HookError("connector_input_closed")
        try:
            self.process.stdin.write(compact(value) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, ConnectionError) as exc:
            raise HookTransportError("connector_input_lost") from exc

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        if self.process.stdout is None:
            raise HookError("connector_output_closed")
        line = self._readline(remaining_lifecycle_seconds(48))
        if not line:
            raise HookTransportError("response_stream_closed")
        response = json.loads(line)
        if response.get("id") != request_id or response.get("error") is not None:
            raise HookError("json_rpc_error")
        result = response.get("result")
        if not isinstance(result, dict):
            raise HookError("invalid_rpc_result")
        return result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError") is True:
            raise tool_failure(name, result)
        content = result.get("content")
        if (
            not isinstance(content, list)
            or len(content) != 1
            or not isinstance(content[0], dict)
            or content[0].get("type") != "text"
        ):
            raise HookError("invalid_tool_content")
        value = json.loads(content[0].get("text", ""))
        if not isinstance(value, dict):
            raise HookError("invalid_tool_value")
        return value

    def close(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def lifecycle_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    global LIFECYCLE_DEADLINE
    previous_deadline = LIFECYCLE_DEADLINE
    if previous_deadline is None:
        LIFECYCLE_DEADLINE = time.monotonic() + LIFECYCLE_BUDGET_SECONDS
    client = None
    try:
        client = McpClient()
        result = client.call(name, arguments)
    except BaseException as exc:
        record_hook_health(name, exc)
        raise
    finally:
        if client is not None:
            client.close()
        LIFECYCLE_DEADLINE = previous_deadline
    record_hook_health(name, None)
    return result


def tool_name(payload: dict[str, Any]) -> str:
    value = payload.get("tool_name", "")
    return value if isinstance(value, str) else ""


def tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input", {})
    if isinstance(value, str):
        value = json.loads(value)
    return value if isinstance(value, dict) else {}


def is_substantive_action(payload: dict[str, Any]) -> bool:
    """Treat any non-Integrity tool as work while keeping memory recovery available."""

    name = tool_name(payload).strip()
    return bool(name) and INTEGRITY_TOOL_RE.search(name) is None and not re.search(
        r"(?i)(?:^|__|codex_app)set_thread_title$", name
    )


def validate_append_tool_input(payload: dict[str, Any]) -> None:
    value = tool_input(payload)
    allowed = {"event_uid", "kind", "summary", "details", "tags", "authority_decision", "context_admission_id"}
    unknown = sorted(str(key)[:40] for key in set(value) - allowed)
    if unknown:
        hint = "; task_id belongs in details.task_id" if "task_id" in unknown else ""
        raise ValueError(f"append arguments contain unknown fields: {', '.join(unknown[:8])}{hint}")
    # The canonical MCP verifies equality with its current admitted context.
    # Mirror the required wire field here without replacing that authority.
    if not _is_digest(value.get("context_admission_id")):
        raise ValueError("context_admission_id must be a sha256 digest")
    event_uid = value.get("event_uid")
    if not isinstance(event_uid, str) or EVENT_UID_RE.fullmatch(event_uid) is None:
        raise ValueError("event_uid must match the bounded immutable client: identity")
    if value.get("kind") not in {"concept", "task", "thought"}:
        raise ValueError("kind must be one of: concept, task, thought")
    summary = value.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2_000:
        raise ValueError("summary must contain 1 to 2000 characters")
    details = value.get("details", {})
    if not isinstance(details, dict):
        raise TypeError("details must be an object")
    tags = value.get("tags", [])
    if (
        not isinstance(tags, list)
        or len(tags) > 20
        or not all(isinstance(tag, str) and 1 <= len(tag.strip()) <= 80 for tag in tags)
    ):
        raise ValueError("tags must be a bounded string array")
    authority = value.get("authority_decision")
    if "authority_decision" in value and not isinstance(authority, dict):
        raise TypeError("authority_decision must be an object")


def validate_context_presentation(
    context: dict[str, Any], expected_protocol: str
) -> dict[str, Any] | None:
    protocol = context.get("protocol")
    if protocol != expected_protocol:
        raise HookError("model_mcp_context_presentation_mismatch")
    if protocol.endswith("/context-admission/v1"):
        return None
    if protocol != "integrity-client-memory-mcp/v3/context-admission/v2":
        raise HookError("model_mcp_context_protocol_invalid")
    if context.get("presentation_mode") != "adaptive":
        raise HookError("model_mcp_context_mode_invalid")
    mind_envelope = context.get("mind")
    if not isinstance(mind_envelope, dict):
        raise HookError("model_mcp_mind_envelope_invalid")
    admission = mind_envelope.get("admission_receipt")
    capsule = mind_envelope.get("mind")
    selection = mind_envelope.get("selection_receipt")
    if not all(isinstance(value, dict) for value in (admission, capsule, selection)):
        raise HookError("model_mcp_context_selection_missing")
    assert isinstance(admission, dict)
    assert isinstance(capsule, dict)
    assert isinstance(selection, dict)
    if capsule.get("protocol") != "integrity-client-memory-mcp/v3/context-capsule/v1":
        raise HookError("model_mcp_context_capsule_protocol_invalid")
    if capsule.get("memory_source") != "canonical-seed-action-log":
        raise HookError("model_mcp_context_capsule_source_invalid")
    if capsule.get("home_record_count") != 0 or capsule.get("production_authority") is not False:
        raise HookError("model_mcp_context_capsule_boundary_invalid")
    source_projection = capsule.get("source_projection")
    if not isinstance(source_projection, dict) or source_projection.get("complete") is not False:
        raise HookError("model_mcp_context_source_projection_invalid")
    projection_digest = admission.get("projection_digest")
    if not isinstance(projection_digest, str) or DIGEST_RE.fullmatch(projection_digest) is None:
        raise HookError("model_mcp_projection_digest_invalid")
    if source_projection.get("projection_digest") != projection_digest:
        raise HookError("model_mcp_context_source_projection_mismatch")
    if (
        selection.get("protocol") != ("integrity-client-memory-mcp/v3/adaptive-context-selection/v1")
        or selection.get("mode") != "adaptive"
    ):
        raise HookError("model_mcp_context_selection_protocol_invalid")
    if selection.get("policy_version") != "adaptive-context-v1":
        raise HookError("model_mcp_context_selection_policy_invalid")
    if selection.get("stop_reason") not in {
        "bounded-projection-complete",
        "candidate-cap-reached",
        "byte-budget-exhausted",
    }:
        raise HookError("model_mcp_context_selection_stop_reason_invalid")
    if selection.get("truncated") is not True or not isinstance(
        selection.get("candidates_truncated"), bool
    ):
        raise HookError("model_mcp_context_selection_truncation_invalid")
    if selection.get("source_projection_digest") != projection_digest:
        raise HookError("model_mcp_context_selection_source_mismatch")
    if (
        selection.get("home_record_count") != 0
        or selection.get("production_authority") is not False
    ):
        raise HookError("model_mcp_context_selection_boundary_invalid")
    max_context_bytes = selection.get("max_context_bytes")
    capsule_bytes = selection.get("capsule_bytes")
    max_candidates = selection.get("max_candidates")
    candidate_cap = selection.get("transport_candidate_cap")
    integer_values = (max_context_bytes, capsule_bytes, max_candidates, candidate_cap)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
        raise HookError("model_mcp_context_selection_bounds_invalid")
    assert isinstance(max_context_bytes, int)
    assert isinstance(capsule_bytes, int)
    assert isinstance(max_candidates, int)
    assert isinstance(candidate_cap, int)
    if not (
        8_192 <= max_context_bytes <= 262_144
        and 1 <= capsule_bytes <= max_context_bytes
        and 1 <= candidate_cap <= max_candidates <= 50
    ):
        raise HookError("model_mcp_context_selection_bounds_invalid")
    for field in ("source_projection_bytes", "intent_term_count"):
        value = selection.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HookError("model_mcp_context_selection_counts_invalid")
    if selection["source_projection_bytes"] < 1:
        raise HookError("model_mcp_context_selection_counts_invalid")
    if not isinstance(selection.get("available_candidates"), dict) or not isinstance(
        selection.get("selected_candidates"), dict
    ):
        raise HookError("model_mcp_context_selection_counts_invalid")
    encoded_capsule = compact(capsule).encode("utf-8")
    if len(encoded_capsule) != capsule_bytes:
        raise HookError("model_mcp_context_capsule_size_mismatch")
    if selection.get("capsule_digest") != digest_object(capsule):
        raise HookError("model_mcp_context_capsule_digest_mismatch")
    receipt_id = selection.get("receipt_id")
    if not isinstance(receipt_id, str) or DIGEST_RE.fullmatch(receipt_id) is None:
        raise HookError("model_mcp_context_selection_receipt_invalid")
    receipt_core = dict(selection)
    receipt_core.pop("receipt_id", None)
    if receipt_id != digest_object(receipt_core):
        raise HookError("model_mcp_context_selection_receipt_mismatch")
    validate_architecture_presentation(context.get("architecture"), admission)
    identity = (
        context["capabilities"].get("contract_version"),
        context["capabilities"].get("facade", {}).get("server_version"),
    )
    if identity == ("1.9.0", SERVER_VERSION):
        expected_status = (
            "stopped" if admission.get("coordination_stop_required") is True else "ready"
        )
        validate_authority_contract(
            context.get("snapshot", {}).get("authority_contract"), "not-evaluated"
        )
        validate_authority_contract(context.get("authority_contract"), expected_status)
    return selection


def semantic_cadence(state: dict[str, Any], *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Return the bounded cross-turn semantic checkpoint state."""

    if state.get("semantic_checkpoint_open") is not True:
        return {"open": False, "due": False, "age_seconds": 0, "actions": 0}
    actions = state.get("semantic_checkpoint_actions")
    started_value = state.get("semantic_checkpoint_started_utc")
    if (
        isinstance(actions, bool)
        or not isinstance(actions, int)
        or actions < 1
        or not isinstance(started_value, str)
        or not started_value
    ):
        return {
            "open": True,
            "due": True,
            "age_seconds": SEMANTIC_CADENCE_MAX_AGE_SECONDS,
            "actions": max(1, actions) if isinstance(actions, int) else 1,
            "state_invalid": True,
        }
    try:
        started = dt.datetime.fromisoformat(started_value)
    except ValueError:
        started = None
    current = now or dt.datetime.now(dt.UTC)
    if started is None or started.tzinfo is None or current.tzinfo is None:
        return {
            "open": True,
            "due": True,
            "age_seconds": SEMANTIC_CADENCE_MAX_AGE_SECONDS,
            "actions": actions,
            "state_invalid": True,
        }
    age_seconds = max(
        0,
        int((current.astimezone(dt.UTC) - started.astimezone(dt.UTC)).total_seconds()),
    )
    timed_work = (
        state.get("semantic_checkpoint_mutation_seen") is True
        or actions >= SEMANTIC_CADENCE_MIN_TIMED_ACTIONS
    )
    return {
        "open": True,
        "due": actions >= SEMANTIC_CADENCE_MAX_ACTIONS
        or (timed_work and age_seconds >= SEMANTIC_CADENCE_MAX_AGE_SECONDS),
        "age_seconds": age_seconds,
        "actions": actions,
        "mutation_seen": state.get("semantic_checkpoint_mutation_seen") is True,
        "state_invalid": False,
    }


def mark_semantic_progress(state: dict[str, Any], *, tool: str, mutation: bool) -> dict[str, Any]:
    if state.get("semantic_checkpoint_open") is not True:
        state["semantic_checkpoint_open"] = True
        state["semantic_checkpoint_started_utc"] = utc_now()
        state["semantic_checkpoint_actions"] = 0
        state["semantic_checkpoint_mutation_seen"] = False
    actions = state.get("semantic_checkpoint_actions", 0)
    if isinstance(actions, bool) or not isinstance(actions, int) or actions < 0:
        actions = SEMANTIC_CADENCE_MAX_ACTIONS
    state["semantic_checkpoint_actions"] = min(actions + 1, 1_000_000)
    state["semantic_checkpoint_mutation_seen"] = bool(
        state.get("semantic_checkpoint_mutation_seen") is True or mutation
    )
    state["semantic_checkpoint_last_tool"] = tool[:256]
    return semantic_cadence(state)


def close_semantic_checkpoint(state: dict[str, Any], *, event_id: object) -> None:
    state["semantic_checkpoint_open"] = False
    state["semantic_checkpoint_actions"] = 0
    state["semantic_checkpoint_mutation_seen"] = False
    state["semantic_checkpoint_event_id"] = event_id
    state["semantic_checkpoint_closed_utc"] = utc_now()
    state.pop("semantic_checkpoint_started_utc", None)
    state.pop("semantic_checkpoint_last_tool", None)
    state.pop("semantic_checkpoint_notice_key", None)


def new_semantic_notice(state: dict[str, Any]) -> bool:
    """Emit once per checkpoint/disposition, not once per tool or counter tick."""
    if not semantic_cadence(state)["due"]:
        return False
    disposition = (
        "ready" if append_ready(state) else
        "unknown" if state.get("append_outcome") == "unknown-outcome" else
        "spent" if state.get("append_attempted") is True else "unavailable"
    )
    key = f"{state.get('semantic_checkpoint_started_utc', '')}:{disposition}"
    if state.get("semantic_checkpoint_notice_key") == key:
        return False
    state["semantic_checkpoint_notice_key"] = key
    return True


def semantic_context(state: dict[str, Any]) -> str:
    cadence = semantic_cadence(state)
    if not cadence["open"]:
        return (
            "SEMANTIC CADENCE CLEAR: event-per-turn=false; create a Seed event only for "
            "a durable decision, result or checkpoint."
        )
    disposition = "OVERDUE" if cadence["due"] else "OPEN"
    if cadence["due"] and append_ready(state):
        instruction = (
            "ADVISORY ONLY: preserve progress in the existing local checkpoint; "
            "cadence does not require a canonical append. Reserve the one append attempt "
            "for a durable result. Mandatory prior ChangeIntent remains separately required."
        )
    elif cadence["due"] and state.get("append_outcome") == "unknown-outcome":
        instruction = (
            "ADVISORY ONLY: prior append outcome is unknown; continue work and "
            "preserve the checkpoint debt. Do not retry; reconcile event_uid."
        )
    elif cadence["due"] and state.get("append_attempted") is True:
        instruction = (
            "ADVISORY ONLY: the current turn already used its one append attempt; "
            "continue work and preserve the checkpoint debt for a later admitted turn. "
            "Do not attempt another append in this turn."
        )
    elif cadence["due"]:
        instruction = (
            "ADVISORY ONLY: canonical append readiness is unavailable; continue work, "
            "preserve the checkpoint debt, and append after a live/current registration exists."
        )
    else:
        instruction = (
            "Continue normally; keep intermediate progress locally and append a durable result. "
            "Cadence alone does not require a canonical write."
        )
    return (
        f"SEMANTIC CHECKPOINT {disposition}: age_seconds={cadence['age_seconds']} "
        f"actions={cadence['actions']} event_per_turn=false. {instruction}"
    )


def find_document(value: Any, predicate: Any, depth: int = 0) -> dict[str, Any] | None:
    if depth > 24:
        return None
    if isinstance(value, dict):
        if value.get("protocol") == _compact_admission.PROTOCOL:
            try:
                value = _compact_admission.resolve_wrapper(value)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
                raise HookError("compact_artifact_" + type(exc).__name__) from None
        if value.get("protocol") == _compact_view.APPEND_PROTOCOL:
            try:
                value = _compact_view.resolve_append(value)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
                raise HookError("compact_append_artifact_" + type(exc).__name__) from None
        if predicate(value):
            return value
        for child in value.values():
            found = find_document(child, predicate, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_document(child, predicate, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            return find_document(json.loads(value), predicate, depth + 1)
        except json.JSONDecodeError:
            return None
    return None


def next_turn_memory_generation(state: dict[str, Any]) -> int:
    value = state.get("turn_memory_generation", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        value = 0
    return value + 1


def clear_turn_memory_registration(state: dict[str, Any]) -> None:
    for name in (
        "turn_memory_registration_id",
        "turn_memory_namespace_fingerprint",
        "turn_memory_opened_utc",
        "turn_memory_terminal_receipt_id",
        "turn_memory_gap_receipt_id",
        "turn_memory_failure",
    ):
        state.pop(name, None)


def preserve_turn_memory_recovery_handle(state: dict[str, Any]) -> None:
    """Retain bounded identities whose canonical open outcome is unresolved."""

    handle = state.get("turn_memory_unresolved_handle")
    if not isinstance(handle, dict):
        return
    handles = state.get("turn_memory_recovery_handles")
    if not isinstance(handles, list):
        handles = []
    identity = digest_object(handle)
    retained = [item for item in handles if isinstance(item, dict)]
    if not any(digest_object(item) == identity for item in retained):
        retained.append(handle)
    state["turn_memory_recovery_handles"] = retained[-8:]
    state.pop("turn_memory_unresolved_handle", None)


def append_ready(state: dict[str, Any]) -> bool:
    return bool(
        state.get("model_mcp_admission_status") == "ready"
        and state.get("write_plane_status") == "ready"
        and state.get("coordination_stop_required") is not True
        and state.get("turn_memory_status") == "open"
        and state.get("turn_memory_lease") == "live"
        and state.get("turn_memory_queue") == "current"
        and _is_digest(state.get("turn_memory_registration_id"))
        # A mandatory checkpoint must be satisfiable under the one-attempt guard.
        and state.get("append_attempted") is not True
        and state.get("append_outcome") != "unknown-outcome"
    )


def detach_turn_memory(state: dict[str, Any], reason: object) -> None:
    clear_turn_memory_registration(state)
    state.update(
        {
            "admission_status": "detached",
            "model_mcp_admission_status": "invalid",
            "turn_memory_status": "detached",
            "turn_memory_lease": "expired",
            "turn_memory_queue": "recovery",
            "turn_memory_lease_updated_utc": utc_now(),
            "turn_memory_failure": str(reason)[:300],
            "coordination_stop_required": False,
            "route_disposition": "detached",
            "write_plane_status": "unavailable",
        }
    )


def open_admitted_turn_memory(identity: str, state: dict[str, Any]) -> dict[str, Any]:
    global LIFECYCLE_DEADLINE
    current_turn = state.get("turn_memory_intent_id", state.get("turn_id"))
    prompt_sha256 = state.get("prompt_sha256")
    if not isinstance(current_turn, str) or not current_turn:
        raise HookError("turn_registration_turn_missing")
    if not isinstance(prompt_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", prompt_sha256):
        raise HookError("turn_registration_prompt_missing")
    machine = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
    arguments = {
        "machine_id": f"machine:{machine}",
        "thread_id": identity,
        "turn_id": current_turn,
        "prompt_sha256": prompt_sha256,
    }
    state["turn_memory_unresolved_handle"] = {
        **arguments,
        "generation": state.get("turn_memory_generation"),
    }
    LIFECYCLE_DEADLINE = time.monotonic() + LIFECYCLE_BUDGET_SECONDS
    brokered = take_broker_registration(state)
    try:
        if brokered is not None:
            opened = brokered  # validated below exactly like a hook-opened receipt
            state["turn_memory_opened_by"] = "broker"
        else:
          try:
            opened = lifecycle_call("integrity_turn_memory_open", arguments)
          except HookTransportError:
            remaining_lifecycle_seconds(1)
            opened = lifecycle_call("integrity_turn_memory_open", arguments)
    finally:
        LIFECYCLE_DEADLINE = None
    receipt = opened.get("receipt")
    if not isinstance(receipt, dict):
        raise HookError("turn_registration_receipt_missing")
    if (
        receipt.get("terminal_required") is not True
        or receipt.get("production_authority") is not False
        or receipt.get("prompt_sha256") != prompt_sha256
        or receipt.get("identity") != {
            key: arguments[key] for key in ("machine_id", "thread_id", "turn_id")
        }
        or not _is_digest(receipt.get("receipt_id"))
        or not _is_digest(receipt.get("namespace_fingerprint"))
    ):
        raise HookError("turn_registration_invalid")
    state.pop("turn_memory_unresolved_handle", None)
    return receipt


def _transcript_text(row: dict[str, Any]) -> str | None:
    message = row.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    parts = []
    for item in content:
        if not isinstance(item, dict):
            return None
        if item.get("type") == "tool_result":
            return None
        if item.get("type") == "text" and isinstance(item.get("text"), str):
            parts.append(item["text"])
    return "".join(parts)


def harness_prompt_origin(payload: dict[str, Any], intent: str) -> tuple[str, str] | None:
    """(turnOrigin, promptSource) Claude Code recorded for the latest prompt row.

    Diagnostic only: the row must belong to this session and carry exactly
    this prompt text, but the payload has no per-invocation prompt id, so an
    older identical row cannot be excluded.  Callers must never suppress the
    owner lifecycle on this result; unproven returns None.
    """

    path = payload_value(payload, "transcript_path", "transcriptPath", default="")
    try:
        session = session_id(payload)
    except HookError:
        return None  # diagnostic only: never fail the hook
    if not isinstance(path, str) or not path or not session:
        return None
    try:
        transcript = Path(path)
        if transcript.is_symlink() or not transcript.is_file():
            return None
        size = transcript.stat().st_size
        with transcript.open("rb") as stream:
            stream.seek(max(0, size - TRANSCRIPT_TAIL_BYTES))
            tail = stream.read(TRANSCRIPT_TAIL_BYTES)
    except OSError:
        return None
    for line in reversed(tail.splitlines()):
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if (
            not isinstance(row, dict)
            or row.get("type") != "user"
            or row.get("isMeta") is True
            or row.get("turnCompanion") is True
        ):
            continue
        text = _transcript_text(row)
        if text is None:
            continue  # tool results are user rows too
        if text != intent or row.get("sessionId") != session:
            return None
        origin, source = row.get("turnOrigin"), row.get("promptSource")
        if isinstance(origin, str) and isinstance(source, str):
            return origin, source
        return None
    return None


def _harness_prompt_record(row: Any) -> tuple[str, tuple[str, str] | None, float | None] | None:
    """(text, origin, epoch) of one harness prompt record, or None.

    Claude Code records a prompt either as a user row (turnOrigin/promptSource)
    or, when it arrives mid-turn, as a queued_command attachment
    (origin.kind/commandMode).  Queue-operation rows carry no origin: skipped.
    """

    if not isinstance(row, dict):
        return None
    try:
        epoch = dt.datetime.fromisoformat(str(row.get("timestamp")).replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError, OSError):
        epoch = None  # untrusted diagnostic JSON; Windows rejects out-of-platform dates
    if row.get("type") == "user":
        if row.get("isMeta") is True or row.get("turnCompanion") is True:
            return None
        text = _transcript_text(row)
        if text is None:
            return None
        origin, source = row.get("turnOrigin"), row.get("promptSource")
        pair = (origin, source) if isinstance(origin, str) and isinstance(source, str) else None
        return text, pair, epoch
    attachment = row.get("attachment")
    if row.get("type") == "attachment" and isinstance(attachment, dict) and attachment.get("type") == "queued_command":
        text = attachment.get("prompt")
        if not isinstance(text, str):
            return None
        kind = (attachment.get("origin") or {}).get("kind") if isinstance(attachment.get("origin"), dict) else None
        if kind == "task-notification" and attachment.get("commandMode") == "task-notification":
            pair = ("task_notification", "system")
        elif kind == "human":
            pair = ("human", str(attachment.get("commandMode")))
        elif kind == "peer":
            # A message from another Claude session (SendMessage): not an owner intent.
            pair = ("peer", "cross-session")
        else:
            pair = None
        return text, pair, epoch
    return None


def previous_prompt_origin(payload: dict[str, Any], state: dict[str, Any]) -> tuple[str, str] | None:
    """(turnOrigin, promptSource) of the previous turn's prompt record.

    Claude Code writes a prompt record to the transcript only after its
    UserPromptSubmit hooks ran, so the current one is never visible here; the
    previous turn's record is.  It must match the exact prompt_sha256 the hook
    bound, the same session, and a time window around that turn's staging;
    zero or several matches are unproven (owner).  Diagnostic only.
    """

    prompt_sha256 = state.get("prompt_sha256")
    if not isinstance(prompt_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", prompt_sha256):
        return None
    try:
        staged = dt.datetime.fromisoformat(
            str(state.get("turn_ref_expires_utc")).replace("Z", "+00:00")
        ).timestamp() - turn_envelope.TTL_SECONDS
    except (ValueError, OverflowError, OSError):
        return None
    path = payload_value(payload, "transcript_path", "transcriptPath", default="")
    try:
        session = session_id(payload)
    except HookError:
        return None
    if not isinstance(path, str) or not path or not session:
        return None
    try:
        transcript = Path(path)
        if transcript.is_symlink() or not transcript.is_file():
            return None
        size = transcript.stat().st_size
        with transcript.open("rb") as stream:
            stream.seek(max(0, size - PREVIOUS_PROMPT_TAIL_BYTES))
            tail = stream.read(PREVIOUS_PROMPT_TAIL_BYTES)
    except OSError:
        return None
    matches = []
    for line in tail.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(row, dict) or row.get("sessionId") != session:
            continue
        record = _harness_prompt_record(row)
        if record is None:
            continue
        text, pair, epoch = record
        if sha256_text(text) != prompt_sha256:
            continue
        if epoch is None or not staged - PREVIOUS_PROMPT_WINDOW_SECONDS <= epoch <= staged + PREVIOUS_PROMPT_WINDOW_SECONDS:
            continue
        matches.append(pair)
    return matches[0] if len(matches) == 1 else None


def handle_prompt(event: str, payload: dict[str, Any], identity: str) -> None:
    intent = (
        prompt(payload)
        if event == "UserPromptSubmit"
        else "Initialize this fresh subagent with current canonical project coordination and safety context."
    )
    # Never suppresses the owner lifecycle: a misclassified owner prompt still
    # gets its turn_ref; the only effect is that this turn is not counted
    # toward the offline-notice streak.
    origin = harness_prompt_origin(payload, intent) if event == "UserPromptSubmit" else None
    probable_notification = event == "UserPromptSubmit" and (
        origin in NON_OWNER_PROMPT_ORIGINS
        # origin is None when the prompt row is not yet in the transcript at
        # UserPromptSubmit time (Claude Desktop); the leading harness
        # banner/tag is then the only signal. Advisory text only, lifecycle unchanged.
        or (origin in (None, ("sdk", "sdk")) and HARNESS_PROMPT_TAG_RE.match(intent) is not None)
    )
    current_turn = turn_id(payload) or f"turn:{uuid.uuid4()}"
    state = load_state(identity)
    late_admission = record_late_admission(intent, state) if event == "UserPromptSubmit" else None
    if (
        event == "UserPromptSubmit"
        and state.get("turn_kind") != NOTIFICATION_TURN_KIND
        and previous_prompt_origin(payload, state) in NON_OWNER_PROMPT_ORIGINS
    ):
        # Retroactive, diagnostic only: the finished previous turn was a harness
        # notification, so it says nothing about the MCP connection.
        state["turn_kind"] = NOTIFICATION_TURN_KIND
    offline_notice = admission_offline_notice(state, probable_notification)
    interrupted = _turn_guard.interrupted_owner_turn(state) if _turn_guard is not None else None
    interrupted_gap = record_interrupted_gap(interrupted, state)
    declined = state.pop("turn_guard_declined_registration", None)
    if isinstance(declined, str) and declined.startswith("sha256:"):
        notice = (
            f"TURN MEMORY DECLINED CLOSE (ISS-018): the previous turn changed state and ended without "
            f"closing registration {declined}; a signed gap was recorded. In this turn call admission, "
            "append one event with that turn's outcome, and close both that registration and this "
            "turn's registration with the event's receipt."
        )
        interrupted_gap = (interrupted_gap + chr(10) + notice) if interrupted_gap else notice
    unsent = state.pop(APPEND_NOT_SENT_STATE, None)
    if isinstance(unsent, str):
        notice = (
            "APPEND NOT SENT IN THE PREVIOUS TURN (ISS-066): nothing was written. After admission, append "
            "that event once" + (f" with the same event_uid {unsent}" if unsent else "") + "."
        )
        interrupted_gap = (interrupted_gap + chr(10) + notice) if interrupted_gap else notice
    generation = next_turn_memory_generation(state)
    prior_turn_ref = state.get("turn_ref")
    if isinstance(prior_turn_ref, str):
        try:
            turn_envelope.retire(prior_turn_ref, preserve_claimed=True)
        except (OSError, turn_envelope.TurnEnvelopeError):
            pass
    envelope = turn_envelope.stage(
        intent,
        machine_id=machine_id(),
        thread_id=identity,
        turn_id=current_turn,
        generation=generation,
    )
    preserve_turn_memory_recovery_handle(state)
    clear_turn_memory_registration(state)
    if _turn_guard is not None:
        _turn_guard.reset_turn(state)
        if probable_notification:
            # The model continues the owner's work inside this notification turn.
            _turn_guard.carry_interrupted(state, interrupted)
    state.update(
        {
            "admission_status": "provisional",
            "turn_id": current_turn,
            # The native turn can contain several owner intents (steering).
            # The staged/authenticated envelope pins retries to this exact intent.
            "turn_memory_intent_id": "intent:" + envelope["turn_ref_digest"][7:],
            "prompt_sha256": sha256_text(intent),
            "prompt_bytes": envelope["prompt_bytes"],
            "prompt_segment_count": envelope["segment_count"],
            "prompt_coverage": envelope["prompt_coverage"],
            "prompt_truncation": False,
            "turn_ref": envelope["turn_ref"],
            "turn_ref_digest": envelope["turn_ref_digest"],
            "turn_ref_expires_utc": envelope["expires_utc"],
            "coordination_stop_required": False,
            "route_disposition": "pending",
            "write_plane_status": "pending",
            "model_mcp_admission_status": "required",
            "model_mcp_admission_attempted": False,
            "model_mcp_read_seal_retry_count": 0,
            "model_mcp_transport_retry_count": 0,
            "production_authority": False,
            "home_record_count": 0,
            "turn_memory_generation": generation,
            "turn_memory_status": "provisional",
            "turn_memory_lease": "provisional",
            "turn_memory_queue": "current",
            "turn_memory_lease_updated_utc": utc_now(),
            "turn_kind": NOTIFICATION_TURN_KIND if probable_notification else "owner",
            # prompt_sha256 binds the staged envelope text; for an image-only
            # message that is the fixed marker, declared by this kind.
            "prompt_kind": prompt_kind(payload) if event == "UserPromptSubmit" else "subagent",
        }
    )
    write_turn_hint(identity, state)
    state.pop("model_mcp_expected_context_protocol", None)
    state.pop("model_mcp_selection_receipt_id", None)
    state.pop("retry_disposition", None)
    if state.get("append_outcome") != "unknown-outcome":
        state["append_outcome"] = "not-started"
        state["append_attempted"] = False
        state["automatic_retry_allowed"] = True
    save_state(identity, state)
    output_context(
        event,
        (offline_notice + "\n" if offline_notice else "")
        + (interrupted_gap + "\n" if interrupted_gap else "")
        + (
            f"INTEGRITY LATE ADMISSION RESULT: background task {late_admission} field-matched its own "
            "earlier intent (diagnostic, not cryptographic verification, not native admission) and is "
            "recorded for it only; it is not this intent's receipt.\n"
            if late_admission
            else ""
        )
        + (
            "INTEGRITY client: HARNESS NOTIFICATION TURN (task notification / peer event; diagnostic, "
            "unsigned). Owner rule: a read-only notification turn does NOT call "
            "integrity_context_admission_current_turn and owes no close. ISS-011: "
            "if this turn will change state (edit/write files, run shell commands, send messages) or "
            "append an Integrity event, call admission with the turn_ref below before the first such "
            "tool and close the registration before finishing.\n"
            if probable_notification and state.get("turn_guard_interrupted_owner") is not True
            else (
                "INTEGRITY client: this notification arrived inside an unfinished owner turn. The "
                "owner's work continues in this turn, so the notification exemption does not apply: "
                "call integrity_context_admission_current_turn with the turn_ref below and close the "
                "turn before finishing.\n"
                if probable_notification
                else ""
            )
        )
        + f"INTEGRITY client READ PLANE PENDING v3\n"
        "No hook-owned Seed admission/snapshot process was opened. No canonical Turn Memory "
        "registration was opened.\n"
        "Invoke integrity_context_admission_current_turn exactly once in the model-owned MCP "
        f"session with turn_ref={envelope['turn_ref']!r}, omit limit for adaptive selection and pass "
        'budget={"max_context_bytes": 8192, "max_candidates": 5} so the result fits the tool output limit. '
        "Do not repeat or reconstruct the prompt in tool arguments.\n"
        "Write/action blockers never make the returned read-only Seed snapshot unavailable.\n"
        "MEMORY AUTHORITY: provider=memory-only; target_action=not-evaluated; "
        "provider boundary is not a target denial. coordination scope=integrity-memory-route; "
        "Seed append and external targets are unaffected.\n"
        f"Home=0 canonical_writes=0\nTURN MEMORY PROVISIONAL generation={generation} "
        "lease=provisional queue=current. A canonical registration is created only after the "
        "context admission receipt validates.\n"
        + semantic_context(state),
    )


def admission_gate_reason(state: dict[str, Any], name: str) -> str | None:
    """Admission-first gate (turn-guard.json ``admission_first``); never raises."""

    if _turn_guard is None or not hasattr(_turn_guard, "admission_gate"):
        return None
    try:
        policy = _turn_guard.load_gate_policy(state_root().parent)
        failure_probe = globals().get("last_broker_failure")
        failure = failure_probe() if callable(failure_probe) else None
        reason = _turn_guard.admission_gate(state, name, policy, broker_failure=failure)
    except Exception:  # noqa: BLE001 - the gate fails open
        return None
    if reason:
        _turn_guard.note_gate_denial(state)
    return reason


def deny_gate(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


# A19 (owner decision): every Integrity event summary ends with a separate last line
# «Ключевые слова: …» — 5-8 Russian words or short phrases, the way the owner would name the subject.
# ADVISORY ONLY: the event is never refused because of this line; the model gets a warning and
# keywords-line-health.json counts the results. Codex has its own hook (ProgramData) and is not changed here.
KEYWORDS_HEALTH_FILE = "keywords-line-health.json"  # A19 counters: own file next to hook-health.json, never that file
KEYWORDS_LINE_RE = re.compile(r"^\s*Ключевые слова:\s*(.*?)\s*$")
KEYWORDS_CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")


def keyword_line_problem(summary: Any) -> str | None:
    """None when the last non-empty line is «Ключевые слова: a; b; …» with 5-8 items, at least half of them Cyrillic."""
    if not isinstance(summary, str):
        return "summary is not text"
    lines = [line for line in summary.splitlines() if line.strip()]
    if not lines:
        return "summary is empty"
    match = KEYWORDS_LINE_RE.match(lines[-1])
    if match is None:
        return "the last non-empty line of summary is not «Ключевые слова: …»"
    items = [item.strip() for item in re.split(r"[;,]", match.group(1)) if item.strip()]
    if not 5 <= len(items) <= 8:
        return f"«Ключевые слова» has {len(items)} items, expected 5-8"
    russian = sum(1 for item in items if KEYWORDS_CYRILLIC_RE.search(item))
    if russian * 2 < len(items):  # names like HOST1, NODE2, ISS-051 are fine as a minority
        return f"only {russian} of {len(items)} keywords contain Russian (Cyrillic) letters, expected at least half"
    return None


def record_keyword_line(problem: str | None, path: Path | None = None) -> None:
    """Count keyword-line results in keywords-line-health.json (own file; hook-health.json is never read or written)."""
    try:
        target = path if path is not None else state_root().parent / KEYWORDS_HEALTH_FILE
        health: dict[str, Any] = {}
        if target.is_file() and not target.is_symlink():
            loaded = json.loads(target.read_text(encoding="utf-8"))
            health = loaded if isinstance(loaded, dict) else {}
        key = "keywords_line_missing" if problem is not None else "keywords_line_ok"
        previous = health.get(key)
        health[key] = previous + 1 if isinstance(previous, int) and previous >= 0 else 1
        if problem is not None:
            health["keywords_line_last_missing_utc"] = utc_now()
            health["keywords_line_last_problem"] = problem[:120]
        health.setdefault("protocol", "integrity-memory/keywords-line-health/v1")
        temporary = target.with_name(f".keywords-health-{uuid.uuid4().hex}.tmp")
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(compact(health) + "\n")
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except Exception:  # noqa: BLE001 - advisory, never blocks a turn
        return


def handle_pre_tool(payload: dict[str, Any], identity: str, state: dict[str, Any]) -> None:
    name = tool_name(payload)
    arguments = tool_input(payload)
    encoded = compact(arguments)
    if re.search(r"(?is)\bdelete\s+from\s+.{0,64}\bevents\b", encoded):
        deny("canonical Action Log events are immutable")
    agent = subagent_id(payload)
    if agent is not None:
        # ISS-049: the parent's admission-first gate, single-shot flags, retry state and MCP
        # logical context are not the subagent's. Its Integrity calls would consume or rotate
        # them, so they are refused; its other tools still count as the parent turn's actions.
        if INTEGRITY_TOOL_RE.search(name):
            deny(
                f"subagent {agent} shares the parent session; {name.rsplit('__', 1)[-1]} belongs "
                "to the parent's turn. Return your result to the parent agent; the parent records "
                "it in Integrity (ISS-049)."
            )
        if _turn_guard is not None and _turn_guard.note_tool(state, name):
            save_state(identity, state)
        return
    gate = admission_gate_reason(state, name)
    if gate:
        save_state(identity, state)
        deny_gate(gate)
    if _turn_guard is not None and _turn_guard.note_tool(state, name):
        # The Stop guard needs to know that this turn attempted a state change.
        save_state(identity, state)
    retry_pending = state.get("retry_disposition") in {
        "exact-envelope-after-supported-read-seal",
        "exact-envelope-after-pre-send-transport",
    }
    if (
        retry_pending
        and INTEGRITY_TOOL_RE.search(name)
        and not CURRENT_CONTEXT_TOOL_RE.search(name)
    ):
        deny("only the identical current-turn admission is allowed while retry is pending")
    if CONTEXT_TOOL_RE.search(name):
        if state.get("model_mcp_admission_attempted") is True:
            deny("model MCP context admission is single-shot for the current turn")
        if CURRENT_CONTEXT_TOOL_RE.search(name):
            turn_ref = arguments.get("turn_ref")
            if not isinstance(turn_ref, str) or turn_ref != state.get("turn_ref"):
                deny("model MCP turn_ref does not match the current prompt envelope")
            try:
                turn_envelope.arm(
                    turn_ref,
                    machine_id=machine_id(),
                    thread_id=identity,
                    turn_id=str(state.get("turn_id", "")),
                    generation=int(state.get("turn_memory_generation", 0)),
                    prompt_sha256=str(state.get("prompt_sha256", "")),
                )
            except (OSError, ValueError, turn_envelope.TurnEnvelopeError) as exc:
                deny(f"turn envelope cannot be armed: {exc}")
            if retry_pending:
                state.pop("retry_disposition", None)
        else:
            intent = arguments.get("intent")
            if not isinstance(intent, str) or sha256_text(intent) != state.get("prompt_sha256"):
                deny("model MCP intent does not match the current prompt")
        state["model_mcp_admission_attempted"] = True
        state["model_mcp_admission_status"] = "pending"
        state["model_mcp_expected_context_protocol"] = (
            "integrity-client-memory-mcp/v3/context-admission/v1"
            if "limit" in arguments
            else "integrity-client-memory-mcp/v3/context-admission/v2"
        )
        save_state(identity, state)
        return
    if (
        re.search(r"(?i)(?:^|__)integrity_turn_memory_close$", name)
        and arguments.get("outcome") == "no-event"
        and state.get("append_outcome") in {"created", "duplicate"}
        and arguments.get("registration_id") == state.get("turn_memory_registration_id")
    ):
        # ISS-019: a turn that appended an event must not be closed as no-event;
        # the signed terminal receipt cannot be corrected afterwards.
        deny(
            "this turn appended event "
            + str(state.get("append_event_id"))
            + "; close it with outcome=events and events=[{event_uid: "
            + repr(state.get("append_event_uid"))
            + ", event_id: "
            + str(state.get("append_event_id"))
            + ", request_sha256: "
            + repr(state.get("append_request_sha256"))
            + "}] instead of no-event"
        )
    if INTEGRITY_TOOL_RE.search(name) and not APPEND_TOOL_RE.search(name):
        return
    if APPEND_TOOL_RE.search(name):
        try:
            validate_append_tool_input(payload)
        except (TypeError, ValueError) as exc:
            deny(str(exc))
        if state.get("model_mcp_admission_status") != "ready":
            deny("model_mcp_context_admission_required")
        if (
            state.get("turn_memory_status") != "open"
            or state.get("turn_memory_lease") != "live"
            or state.get("turn_memory_queue") != "current"
            or not _is_digest(state.get("turn_memory_registration_id"))
        ):
            deny("turn_memory_registration_required")
        if state.get("append_outcome") == "unknown-outcome":
            deny("prior append outcome is unknown; automatic retry is forbidden")
        if state.get("append_attempted") is True and state.get("append_outcome") == "not-sent":
            deny(
                "the previous append of this turn was not sent (ISS-066: upstream transport lost, "
                "nothing written) and this turn's admitted context is gone; append it in the next turn "
                "with the same event_uid"
            )
        if state.get("append_attempted") is True:
            deny("only one append attempt is allowed in the current turn")
        pending_uid = tool_input(payload).get("event_uid")
        state.update(
            {
                "append_attempted": True,
                "append_outcome": "started",
                "append_pending_event_uid": pending_uid if isinstance(pending_uid, str) else "",
                "unresolved_mutation": True,
                "automatic_retry_allowed": False,
            }
        )
        save_state(identity, state)
        problem = keyword_line_problem(tool_input(payload).get("summary"))
        record_keyword_line(problem)
        if problem is not None:
            output_context(
                "PreToolUse",
                "INTEGRITY KEYWORDS LINE WARNING (advisory; this event is NOT refused): " + problem
                + ". End every event summary with a separate last line «Ключевые слова: …» — 5-8 Russian"
                " words or short phrases, as the owner would say. Do not retry this append; add the line"
                " in the next event.",
            )
        return
    # Cadence tracks local progress; it must not spend the sole append attempt
    # before a terminal result exists. Admission/append/unknown-outcome guards
    # above and target-specific prior authority are unchanged.


# Claude Code does not hand a tool result larger than its output limit to the model or the
# hook; it writes the result under its own project directory and returns a notice instead.
# Two notice forms exist: the MCP token limit ("Output has been saved to <path>.txt", the raw
# text) and persisted output ("Full output saved to: <path>.json", the content blocks).
SPILLED_RESULT_RE = re.compile(
    r"(?:Output has been saved to|Full output saved to:) ([^\r\n]+?\.(?:txt|json))"
)
SPILLED_TOOL_USE_RE = re.compile(r"toolu_[A-Za-z0-9_-]+\.(?:txt|json)\Z")
MAX_SPILLED_RESULT_BYTES = 8 * 1024 * 1024


def spilled_name_matches(name: str, payload: dict[str, Any]) -> bool:
    """The spill file name must belong to this tool call, not to another tool's result."""

    tool = tool_name(payload)
    if tool and name.startswith(tool.replace("__", "-") + "-"):
        return True
    use_id = payload.get("tool_use_id")
    if isinstance(use_id, str) and use_id:
        return name.rsplit(".", 1)[0] == use_id
    return SPILLED_TOOL_USE_RE.match(name) is not None


def spilled_tool_result(response: Any, payload: dict[str, Any] | None = None) -> Any:
    """Load a harness-spilled tool result from the harness's own tool-results directory."""

    match = SPILLED_RESULT_RE.search(json.dumps(response, ensure_ascii=False))
    if match is None:
        return None
    try:
        path = Path(match.group(1).replace("\\\\", "\\")).resolve(strict=True)
        projects = (Path.home() / ".claude" / "projects").resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if (
        projects not in path.parents
        or path.parent.name != "tool-results"
        or not path.is_file()
        or path.stat().st_size > MAX_SPILLED_RESULT_BYTES
        or (payload is not None and not spilled_name_matches(path.name, payload))
    ):
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def reconcile_unknown_append(
    event: str, payload: dict[str, Any], identity: str, state: dict[str, Any]
) -> bool:
    """An exact event_uid lookup that finds the pending immutable event resolves the unknown outcome."""

    pending = state.get("append_pending_event_uid")
    if state.get("append_outcome") != "unknown-outcome" or not isinstance(pending, str) or not pending:
        return False
    if tool_input(payload).get("event_uid") != pending:
        return False
    lookup = find_document(
        payload.get("tool_response", {}),
        lambda item: str(item.get("protocol", "")).endswith("seed-event-uid-lookup/v1")
        and item.get("outcome") == "found",
    )
    if lookup is None or lookup.get("event_uid") != pending:
        return False
    receipt = lookup.get("receipt") if isinstance(lookup.get("receipt"), dict) else {}
    event_id = receipt.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        return False
    state.update(
        {
            "append_outcome": "created",
            "append_event_id": event_id,
            "append_event_uid": pending,
            "unresolved_mutation": False,
        }
    )
    close_semantic_checkpoint(state, event_id=event_id)
    save_state(identity, state)
    output_context(
        event,
        f"INTEGRITY APPEND RECONCILED: {pending} is canonical event {event_id}; "
        "the unknown outcome is resolved without a retry.",
    )
    return True


_BACKGROUND_TASK_RE = re.compile(
    r'^MCP tool "[^"]*integrity_context_admission_current_turn" was moved to the background '
    r"as task ([a-z0-9]{6,32}) "
)
_NOTIFICATION_RESULT_RE = re.compile(
    r"\A<task-notification>\n<task-id>([a-z0-9]{6,32})</task-id>\n<status>completed</status>\n"
    r"<summary>MCP task \1 \([^)\n]*integrity_context_admission_current_turn\) completed\.</summary>\n"
    r"<result>\n(.*)\n</result>\n</task-notification>\Z",
    re.DOTALL,
)


def harness_background_task(response: Any) -> str | None:
    """Task id when Claude Code moved the admission call to the background."""

    items = response if isinstance(response, list) else [response]
    texts = [
        item.get("text") if isinstance(item, dict) else item
        for item in items
    ]
    if len(texts) != 1 or not isinstance(texts[0], str):
        return None
    match = _BACKGROUND_TASK_RE.match(texts[0])
    return match.group(1) if match else None


_DIGEST_PREFIXED_RE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_DIGEST_HEX_RE = re.compile(r"[a-f0-9]{64}\Z")


def record_late_admission(intent: str, state: dict[str, Any]) -> str | None:
    """Match a background admission result to the intent that requested it.

    The result is compared with the binding saved when the call went to the
    background (never with the current intent).  This is a diagnostic field
    match, not cryptographic receipt verification and not native admission:
    it is recorded as evidence only, no registration is opened for it and no
    current state is replaced.  Only a full match consumes the pending entry;
    a mismatching or malformed notification leaves it for the right result.
    """

    pending = state.get("background_admissions")
    match = _NOTIFICATION_RESULT_RE.match(intent)
    if not isinstance(pending, dict) or match is None or match.group(1) not in pending:
        return None
    task, expected = match.group(1), pending[match.group(1)]
    context_id = None
    try:
        context = json.loads(match.group(2))
        binding = context["prompt_binding"]
        expected_ref = expected.get("turn_ref_digest")
        expected_prompt = expected.get("prompt_sha256")
        context_id = context.get("context_admission_id")
        matched = (
            context.get("production_authority") is False
            and isinstance(expected_ref, str) and _DIGEST_PREFIXED_RE.match(expected_ref) is not None
            and isinstance(expected_prompt, str) and _DIGEST_HEX_RE.match(expected_prompt) is not None
            and isinstance(context_id, str) and _DIGEST_PREFIXED_RE.match(context_id) is not None
            and binding.get("turn_ref_digest") == expected_ref
            and binding.get("prompt_sha256") == expected_prompt
        )
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        matched = False
    receipts = list(state.get("late_admission_receipts") or [])
    receipts.append({
        "task": task,
        "generation": expected.get("turn_memory_generation"),
        "turn_memory_intent_id": expected.get("turn_memory_intent_id"),
        "field_match": matched,
        "verification": "diagnostic-field-match; not cryptographic receipt verification; not native admission",
        "context_admission_id": context_id if matched else None,
        "bound_to_current_intent": False,
    })
    state["late_admission_receipts"] = receipts[-BACKGROUND_ADMISSIONS_KEPT:]
    if matched:
        state["background_admissions"] = {k: v for k, v in pending.items() if k != task}
    return task if matched else None


def _retryable_read_seal_denial(item: dict[str, Any]) -> bool:
    return (
        item.get("reason_code") == "seed_catalog_checkpoint_required"
        and item.get("automatic_retry_allowed") is True
        and item.get("canonical_writes") == 0
        and item.get("retry_disposition") == "exact-envelope-after-supported-read-seal"
    )


def _retryable_pre_send_transport_denial(item: dict[str, Any]) -> bool:
    return (
        item.get("protocol") == "integrity-client/turn-broker-denial/v1"
        and item.get("failure_layer") == "broker-upstream"
        and item.get("request_sent") is False
        and item.get("automatic_retry_allowed") is True
        and item.get("canonical_writes") == 0
        and item.get("retry_disposition") == "exact-envelope-after-pre-send-transport"
    )


def _pre_send_append_transport_denial(item: dict[str, Any]) -> bool:
    """ISS-066: the broker lost its upstream before any byte of this append was written."""
    return (
        item.get("protocol") == "integrity-client/turn-broker-denial/v1"
        and item.get("tool") == "integrity_append_event"
        and item.get("failure_layer") == "broker-upstream"
        and item.get("outcome") == "denied"
        and item.get("request_sent") is False
        and item.get("canonical_writes") == 0
    )


APPEND_NOT_SENT_STATE = "append_not_sent_event_uid"


def _record_unsent_append(event: str, identity: str, state: dict[str, Any]) -> bool:
    """ISS-066: an append that never left the broker wrote nothing and is safe to send again,
    but not in this turn: the admitted logical context died with the upstream transport, the
    broker closes it, and the turn envelope was already consumed by the admission, so no second
    admission (and no admitted append) is possible before the next prompt. Record the outcome
    honestly and carry the event_uid to the next turn."""

    if state.get("append_outcome") != "started":
        return False
    uid = state.get("append_pending_event_uid")
    uid = uid if isinstance(uid, str) else ""
    state["append_outcome"] = "not-sent"
    state["unresolved_mutation"] = False
    state[APPEND_NOT_SENT_STATE] = uid
    save_state(identity, state)
    output_context(
        event,
        "INTEGRITY APPEND NOT SENT (ISS-066): the broker lost its upstream transport before any byte "
        "of this append was sent; canonical_writes=0, nothing was written. The admitted context was "
        "lost with that transport, so this turn cannot append again: do not retry now. In the next "
        "turn, after admission, append the same content once with the same event_uid "
        + (uid or "(the one you used)") + " and close both registrations.",
    )
    return True


def _arm_supported_retry(
    event: str,
    retryable_wal: dict[str, Any] | None,
    retryable_transport: dict[str, Any] | None,
    identity: str,
    state: dict[str, Any],
) -> bool:
    """The one supported retry of the current-turn admission; True when it was armed.

    Moved verbatim from handle_post_tool (ISS-042) and shared with PostToolUseFailure: same
    proofs, same counters (each branch at most once per turn), same state and notices on both
    paths. The read-seal branch is checked first, as before; a failed envelope arm arms nothing.
    """

    if retryable_wal is not None and int(state.get("model_mcp_read_seal_retry_count", 0)) < 1:
        state["model_mcp_read_seal_retry_count"] = 1
        state["model_mcp_admission_attempted"] = False
        state["model_mcp_admission_status"] = "required"
        state["automatic_retry_allowed"] = True
        state["retry_disposition"] = "exact-envelope-after-supported-read-seal"
        save_state(identity, state)
        output_context(
            event,
            "INTEGRITY READ PLANE RETRYABLE: the exact current turn_ref was not consumed. "
            "After the Seed owner completes the supported read-seal recovery, retry "
            "integrity_context_admission_current_turn once with the identical turn_ref. "
            "No other tool is admitted before that retry.",
        )
        return True
    if retryable_transport is not None and int(state.get("model_mcp_transport_retry_count", 0)) < 1:
        try:
            turn_envelope.arm(
                str(state.get("turn_ref", "")),
                machine_id=machine_id(),
                thread_id=identity,
                turn_id=str(state.get("turn_id", "")),
                generation=int(state.get("turn_memory_generation", 0)),
                prompt_sha256=str(state.get("prompt_sha256", "")),
            )
        except (OSError, ValueError, turn_envelope.TurnEnvelopeError):
            return False
        state["model_mcp_transport_retry_count"] = 1
        state["model_mcp_admission_attempted"] = False
        state["model_mcp_admission_status"] = "required"
        state["automatic_retry_allowed"] = True
        state["retry_disposition"] = "exact-envelope-after-pre-send-transport"
        save_state(identity, state)
        output_context(
            event,
            "INTEGRITY TRANSPORT RETRYABLE: no admission request bytes were sent and "
            "the exact current turn_ref remains armed. Retry "
            "integrity_context_admission_current_turn once with the identical turn_ref. "
            "No other Integrity tool is admitted before that retry.",
        )
        return True
    return False


def _failure_document(payload: dict[str, Any]) -> dict[str, Any] | None:
    """ISS-042: a tool that ends in error reaches the hook as PostToolUseFailure, with the
    denial text in `error` and no tool_response (verified live on Claude Code 2.1.321).
    Only the first JSON object counts."""

    text = payload.get("error")
    if not isinstance(text, str):
        return None
    start = text.find("{")
    if start < 0:
        return None
    try:
        value, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def handle_post_tool_failure(
    event: str, payload: dict[str, Any], identity: str, state: dict[str, Any]
) -> None:
    """ISS-042: the supported admission retries on the tool-error path.

    The facade read-seal denial and the broker pre-send transport denial both reach the hook as
    tool errors, so the PostToolUse branches never saw them and the turn stayed single-shot
    without admission. Same proofs and counters via _arm_supported_retry; any other failure keeps
    the previous behaviour (before this step the hook saw no failures at all).
    """

    name = tool_name(payload)
    if subagent_id(payload) is not None:
        return  # ISS-049: a subagent never arms the parent's admission retry
    if APPEND_TOOL_RE.search(name):
        document = _failure_document(payload)
        if document is not None and find_document(document, _pre_send_append_transport_denial) is not None:
            _record_unsent_append(event, identity, state)
        return
    if not CURRENT_CONTEXT_TOOL_RE.search(name):
        return
    if tool_input(payload).get("turn_ref") != state.get("turn_ref"):
        return
    document = _failure_document(payload)
    if document is None:
        return
    _arm_supported_retry(
        event,
        find_document(document, _retryable_read_seal_denial),
        find_document(document, _retryable_pre_send_transport_denial),
        identity,
        state,
    )


def handle_post_tool(
    event: str, payload: dict[str, Any], identity: str, state: dict[str, Any]
) -> None:
    name = tool_name(payload)
    response = payload.get("tool_response", {})
    if subagent_id(payload) is not None and INTEGRITY_TOOL_RE.search(name):
        return  # ISS-049: refused in PreToolUse; never bind a subagent result to the parent turn
    if _turn_guard is not None and INTEGRITY_TOOL_RE.search(name):
        # Evidence for the status notice (the server answered) and the Stop guard (closed).
        _turn_guard.note_mcp_answer(state, name, response)
        closed_now = _turn_guard.note_close(state, name, response)
        # ISS-028: persist the observed close first; nothing after it may lose it.
        save_state(identity, state)
        if closed_now and state.get("turn_memory_close_outcome") == "events":
            close_gapped_with_events(state, tool_input(payload), identity)
            save_state(identity, state)
    if CONTEXT_TOOL_RE.search(name):
        completed = tool_input(payload)
        if CURRENT_CONTEXT_TOOL_RE.search(name):
            superseded = bool(completed.get("turn_ref")) and (
                completed["turn_ref"] != state.get("turn_ref")
            )
        else:
            superseded = bool(completed.get("intent")) and (
                sha256_text(str(completed["intent"])) != state.get("prompt_sha256")
            )
        if superseded:
            output_context(
                event,
                "INTEGRITY SUPERSEDED ADMISSION: late response belongs to an earlier intent; "
                "current admission state is unchanged. Do not bind that receipt to the current intent.",
            )
            return
        background_task = harness_background_task(response) if CURRENT_CONTEXT_TOOL_RE.search(name) else None
        if background_task is not None:
            # Claude Code moved the call to the background: this is not a
            # receipt and not an infrastructure fault.  Remember the exact
            # binding of THIS intent; the late result is matched to it by task id.
            pending = dict(state.get("background_admissions") or {})
            pending[background_task] = {
                key: state.get(key)
                for key in ("turn_ref_digest", "prompt_sha256", "turn_memory_generation", "turn_memory_intent_id")
            }
            state["background_admissions"] = dict(list(pending.items())[-BACKGROUND_ADMISSIONS_KEPT:])
            state["model_mcp_admission_status"] = "background-pending"
            save_state(identity, state)
            output_context(
                event,
                f"INTEGRITY ADMISSION MOVED TO BACKGROUND (task {background_task}): no receipt yet, "
                "not an infrastructure fault; the turn is not detached. The late result belongs to "
                "this intent only and is never bound to a later one. Do not call admission again "
                "for this intent.",
            )
            return
        def is_context(item: dict[str, Any]) -> bool:
            return any(
                str(item.get("protocol", "")).endswith(suffix)
                for suffix in ("/context-admission/v1", "/context-admission/v2")
            )

        context = find_document(response, is_context)
        if context is None:
            # A result above Claude Code's output limit reaches the hook only as a notice.
            context = find_document(spilled_tool_result(response, payload), is_context)
        retryable_wal = find_document(response, _retryable_read_seal_denial)
        retryable_transport = find_document(response, _retryable_pre_send_transport_denial)
        if (
            context is None
            and CURRENT_CONTEXT_TOOL_RE.search(name)
            and _arm_supported_retry(event, retryable_wal, retryable_transport, identity, state)
        ):
            return
        try:
            if context is None or context.get("production_authority") is not False:
                raise HookError("model_mcp_context_receipt_missing")
            if context.get("home_record_count") != 0 or context.get("canonical_writes") != 0:
                raise HookError("model_mcp_context_boundary_invalid")
            expected_protocol = state.get("model_mcp_expected_context_protocol")
            if not isinstance(expected_protocol, str):
                raise HookError("model_mcp_context_presentation_not_bound")
            negotiated_protocol = negotiated_context_protocol(context, expected_protocol)
            selection = validate_context_presentation(context, negotiated_protocol)
            if CURRENT_CONTEXT_TOOL_RE.search(name):
                binding = context.get("prompt_binding")
                if not isinstance(binding, dict):
                    raise HookError("model_mcp_prompt_binding_missing")
                expected_binding = {
                    "turn_ref_digest": state.get("turn_ref_digest"),
                    "prompt_sha256": state.get("prompt_sha256"),
                    "prompt_bytes": state.get("prompt_bytes"),
                    "segment_count": state.get("prompt_segment_count"),
                    "prompt_coverage": "text-only",
                    "truncation": False,
                }
                if any(binding.get(key) != value for key, value in expected_binding.items()):
                    raise HookError("model_mcp_prompt_binding_mismatch")
            snapshot = context["snapshot"]
            mind_receipt = context["mind"]["admission_receipt"]
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            detach_turn_memory(state, exc)
            save_state(identity, state)
            output_context(
                event,
                f"INTEGRITY READ PLANE RECEIPT INVALID: {exc}. TURN MEMORY DETACHED "
                "lease=expired queue=recovery; no validated canonical registration is bound "
                "to this intent. Report the canonical MCP infrastructure fault.",
            )
            return

        state.update(
            {
                "admission_status": "ready",
                "model_mcp_admission_status": "ready",
                "model_mcp_snapshot_id": snapshot["snapshot_id"],
                "model_mcp_mind_receipt_id": mind_receipt["receipt_id"],
                "event_count": snapshot["cursor"]["event_count"],
                "maximum_event_id": snapshot["cursor"]["maximum_event_id"],
                "coordination_stop_required": bool(
                    mind_receipt.get("coordination_stop_required", True)
                ),
                "production_authority": False,
                "home_record_count": 0,
                "model_mcp_negotiated_context_protocol": negotiated_protocol,
                "route_disposition": (
                    "stopped"
                    if mind_receipt.get("coordination_stop_required") is True
                    else "ready"
                ),
            }
        )
        state.pop("retry_disposition", None)
        if selection is not None:
            state["model_mcp_selection_receipt_id"] = selection["receipt_id"]
        architecture = context.get("architecture", {}).get("architecture")
        state["write_plane_status"] = "ready" if architecture else "unavailable"

        try:
            registration = open_admitted_turn_memory(identity, state)
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            preserve_turn_memory_recovery_handle(state)
            clear_turn_memory_registration(state)
            state.update(
                {
                    "turn_memory_status": "registration-unavailable",
                    "turn_memory_lease": "expired",
                    "turn_memory_queue": "recovery",
                    "turn_memory_lease_updated_utc": utc_now(),
                    "turn_memory_failure": str(exc)[:300],
                }
            )
            turn_memory_context = (
                f"TURN MEMORY REGISTRATION UNAVAILABLE (OUTCOME UNRESOLVED): {exc}. The canonical read plane "
                "remains ready; the exact open identity is retained in bounded recovery, "
                "no validated registration id is bound, and append remains gated."
            )
        else:
            state.update(
                {
                    "turn_memory_status": "open",
                    "turn_memory_lease": "live",
                    "turn_memory_queue": "current",
                    "turn_memory_registration_id": registration["receipt_id"],
                    "turn_memory_namespace_fingerprint": registration[
                        "namespace_fingerprint"
                    ],
                    "turn_memory_opened_utc": utc_now(),
                    "turn_memory_lease_updated_utc": utc_now(),
                }
            )
            state.pop("turn_memory_failure", None)
            turn_memory_context = (
                f"TURN MEMORY LIVE registration_id={registration['receipt_id']} "
                f"generation={state['turn_memory_generation']} lease=live queue=current. "
                "Before the final answer close this turn with integrity_turn_memory_close: "
                "outcome=events for the events you appended, otherwise no-event with an honest "
                "reason; a turn that changed state but appended nothing stays coverage debt."
            )
        save_state(identity, state)
        output_context(
            event,
            f"INTEGRITY CANONICAL READ PLANE READY: snapshot={state['model_mcp_snapshot_id']} "
            f"cursor={state['event_count']}/{state['maximum_event_id']} Home=0 "
            "canonical_writes=0. MEMORY AUTHORITY: provider=memory-only; "
            "target_action=not-evaluated; provider boundary is not a target denial; "
            "coordination scope=integrity-memory-route; Seed append and external targets "
            f"are unaffected. {turn_memory_context}",
        )
        return
    if name.endswith("integrity_seed_event_uid") and reconcile_unknown_append(
        event, payload, identity, state
    ):
        return
    if APPEND_TOOL_RE.search(name):
        receipt = find_document(
            response,
            lambda item: str(item.get("protocol", "")).endswith("/append-receipt"),
        )
        if receipt is None:
            receipt = find_document(
                spilled_tool_result(response, payload),
                lambda item: str(item.get("protocol", "")).endswith("/append-receipt"),
            )
        if receipt is None:
            state["append_outcome"] = "unknown-outcome"
            state["unresolved_mutation"] = True
            save_state(identity, state)
            output_context(
                event,
                "INTEGRITY APPEND UNKNOWN-OUTCOME: automatic retry is forbidden; reconcile event_uid.",
            )
            return
        outcome = receipt.get("outcome")
        state["append_outcome"] = outcome
        state["append_event_id"] = receipt.get("event_id")
        state["append_event_uid"] = receipt.get("event_uid")
        state["append_request_sha256"] = receipt.get("request_sha256")
        state["unresolved_mutation"] = outcome not in {"created", "duplicate"}
        if outcome in {"created", "duplicate"}:
            close_semantic_checkpoint(state, event_id=receipt.get("event_id"))
        save_state(identity, state)
        output_context(
            event,
            f"INTEGRITY APPEND PASSIVE WITNESS: outcome={outcome} event_id={receipt.get('event_id')} "
            f"event_uid={receipt.get('event_uid')} request_sha256={receipt.get('request_sha256')} "
            "automatic_retry_allowed=false.",
        )
        return
    mutation = bool(
        MEANINGFUL_TOOL_RE.search(name) or MUTATION_TEXT_RE.search(compact(tool_input(payload)))
    )
    if is_substantive_action(payload):
        if mutation:
            state["unresolved_mutation"] = True
        mark_semantic_progress(state, tool=name, mutation=mutation)
        notice = new_semantic_notice(state)
        save_state(identity, state)
        if notice:
            output_context(event, semantic_context(state))


def guard_stop(event: str, payload: dict[str, Any], identity: str, state: dict[str, Any]):
    """Turn-close guard. Returns (policy, decision); a block is printed and saved here."""

    if _turn_guard is None:
        return {"mode": "off"}, {"action": "none", "reason": "", "why": "guard-module-unavailable"}
    policy = _turn_guard.load_policy(state_root().parent)
    notification_now = False
    if event == "Stop" and state.get("turn_kind") != NOTIFICATION_TURN_KIND:
        # At Stop the current prompt row is in the transcript; classify it now.
        notification_now = previous_prompt_origin(payload, state) in NON_OWNER_PROMPT_ORIGINS
        if notification_now:
            state["turn_kind"] = NOTIFICATION_TURN_KIND
    decision = _turn_guard.stop_decision(
        state, payload, policy, event=event, notification_now=notification_now
    )
    if decision["action"] == "block":
        # Keep the turn_ref and registration live: the model continues this turn.
        _turn_guard.mark_blocked(state)
        save_state(identity, state)
        print(compact(_turn_guard.stop_output(decision)))
    return policy, decision


def handle_stop(
    event: str, identity: str, state: dict[str, Any], payload: dict[str, Any] | None = None
) -> None:
    policy, decision = guard_stop(event, payload or {}, identity, state)
    if decision["action"] == "block":
        return
    if (
        decision.get("why") in {"stop-hook-active", "already-blocked-once"}
        and state.get("turn_memory_close_observed") is not True
        and isinstance(state.get("turn_memory_registration_id"), str)
    ):
        # ISS-018: remember the declined registration for the next prompt of this session.
        state["turn_guard_declined_registration"] = state["turn_memory_registration_id"]
    current_turn_ref = state.get("turn_ref")
    if isinstance(current_turn_ref, str):
        try:
            turn_envelope.retire(current_turn_ref, preserve_claimed=True)
        except (OSError, turn_envelope.TurnEnvelopeError):
            pass
    registration = state.get("turn_memory_registration_id")
    verified_at_close = (
        isinstance(registration, str)
        and bool(registration)
        and state.get("turn_memory_close_observed") is True
        and state.get("turn_memory_status") in {"open", "closed"}
    )
    if verified_at_close:
        # ISS-017: PostToolUse already saw the signed terminal receipt of this
        # registration (turn_guard.note_close). Re-verifying it at Stop costs a cold
        # local broker start (31-38 s against a 35 s read budget) and produced
        # coverage-unobservable without any coverage loss, so it is skipped here.
        state["turn_memory_status"] = "closed"
        state["turn_memory_queue"] = "archive"
        context = "TURN MEMORY TERMINAL RECEIPT OBSERVED at close; Stop re-verification skipped."
    elif isinstance(registration, str) and registration:
        try:
            coverage = lifecycle_call(
                "integrity_turn_memory_gap",
                {"registration_id": registration, "stage": "stop"},
            )
            terminal = coverage.get("terminal_receipt")
            if isinstance(terminal, dict):
                state["turn_memory_status"] = "closed"
                state["turn_memory_queue"] = "archive"
                state["turn_memory_terminal_receipt_id"] = terminal.get("receipt_id")
                context = (
                    f"TURN MEMORY TERMINAL RECEIPT VERIFIED: outcome={terminal.get('outcome')} "
                    f"receipt_id={terminal.get('receipt_id')}."
                )
            else:
                gap = coverage.get("receipt", {})
                state["turn_memory_status"] = "coverage-debt"
                state["turn_memory_queue"] = "recovery"
                state["turn_memory_gap_receipt_id"] = gap.get("receipt_id")
                context = (
                    "TURN MEMORY COVERAGE GAP RECORDED: terminal receipt is missing; "
                    f"gap_receipt_id={gap.get('receipt_id')}. Do not claim no-event."
                )
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            state["turn_memory_status"] = "coverage-unobservable"
            state["turn_memory_queue"] = "recovery"
            state["turn_memory_failure"] = str(exc)[:300]
            context = (
                f"TURN MEMORY COVERAGE UNOBSERVABLE: {exc}. Do not claim this turn is covered."
            )
        state["turn_memory_lease"] = "expired"
        state["turn_memory_lease_updated_utc"] = utc_now()
    elif state.get("turn_memory_status") == "provisional":
        state["turn_memory_lease"] = "expired"
        state["turn_memory_lease_updated_utc"] = utc_now()
        if state.get("model_mcp_admission_attempted") is True:
            state["turn_memory_status"] = "detached"
            state["turn_memory_queue"] = "recovery"
            context = (
                "TURN MEMORY ADMISSION DETACHED: the attempted context admission never "
                "produced a validated receipt; no canonical registration exists and this "
                "local generation is queued for recovery, not coverage debt."
            )
        else:
            state["turn_memory_status"] = "expired-provisional"
            state["turn_memory_queue"] = "archive"
            context = (
                "TURN MEMORY PROVISIONAL EXPIRED: context admission was never attempted, so "
                "no canonical registration or coverage debt exists; the local generation is archived."
            )
    elif state.get("turn_memory_status") == "detached":
        state["turn_memory_lease"] = "expired"
        state["turn_memory_queue"] = "recovery"
        state["turn_memory_lease_updated_utc"] = utc_now()
        context = (
            "TURN MEMORY DETACHED: no validated canonical registration exists; the local "
            "generation remains in recovery and is not coverage debt."
        )
    elif state.get("turn_memory_status") in {
        "registration-unavailable",
        "registration-unresolved",
    }:
        state["turn_memory_lease"] = "expired"
        state["turn_memory_queue"] = "recovery"
        state["turn_memory_lease_updated_utc"] = utc_now()
        context = (
            "TURN MEMORY REGISTRATION UNAVAILABLE: the canonical read plane was admitted, "
            "but no validated registration id is bound; recovery is required and no coverage "
            "gap can be recorded locally."
        )
    else:
        context = "TURN MEMORY COVERAGE UNOBSERVABLE: no canonical registration id."
    if state:
        save_state(identity, state)
    if state.get("append_outcome") == "unknown-outcome":
        context += "\nINTEGRITY APPEND UNKNOWN-OUTCOME: do not retry."
    elif state.get("unresolved_mutation") is True:
        context += "\nINTEGRITY ACTION-PLANE WARNING: meaningful mutation lacks verified closure."
    cadence = semantic_cadence(state)
    if cadence["open"]:
        context += "\n" + semantic_context(state)
    if decision["action"] == "advise" and decision.get("reason"):
        # Operator-visible: a skipped close is no longer silent coverage debt.
        context += "\n" + decision["reason"]
    if event == "Stop" and _turn_guard is not None:
        _turn_guard.record_turn(
            _turn_guard.guard_root(state_root().parent), _turn_guard.turn_record(state, decision, vendor="hook"), policy
        )
    if (
        state.get("turn_memory_status") == "closed"
        and state.get("append_outcome") != "unknown-outcome"
        and state.get("unresolved_mutation") is not True
        and not cadence["open"]
        and decision["action"] != "advise"
    ):
        # A verified terminal receipt needs no operator-visible message on every stop.
        return
    output_context(event, context)


def use_utf8_stdio() -> None:
    """Hook I/O is UTF-8 JSON on every platform; never the Windows ANSI code page."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def read_hook_payload() -> dict[str, Any]:
    use_utf8_stdio()
    raw = sys.stdin.buffer.read().decode("utf-8")
    payload = json.loads(raw) if raw.strip() else {}
    if not isinstance(payload, dict):
        raise HookError("invalid_hook_payload")
    return payload


def _claude_receiving_factory():
    root = Path('~/.claude/integrity-memory')
    config_path = root / 'delegation-config.json'
    config_raw = config_path.read_bytes()
    config = json.loads(config_raw)
    path = root / 'claude_runtime_factory.py'
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError('claude_factory_path_invalid')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != config['claude_module_pins']['claude_runtime_factory']:
        raise ValueError('claude_factory_pin_invalid')
    from types import ModuleType
    module = ModuleType('claude_factory_owning_hook'); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--event",
        required=True,
        choices=(
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "SubagentStart",
            "Stop",
            "SubagentStop",
        ),
    )
    # Claude Code has no CODEX_HOME or Codex MCP registry: its installer passes explicit roots.
    parser.add_argument("--state-root")
    parser.add_argument("--envelope-root")
    parser.add_argument("--transport")
    args = parser.parse_args()
    for value, name in ((args.state_root, "INTEGRITY_CLIENT_STATE_ROOT"),
                        (args.envelope_root, "INTEGRITY_CLIENT_ENVELOPE_ROOT"),
                        (args.transport, "INTEGRITY_CLIENT_MCP_TRANSPORT")):
        if value:
            os.environ[name] = value
    payload = read_hook_payload()
    identity = session_id(payload)
    if identity in ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000003'):
        from types import ModuleType
        path=Path("%ProgramData%/OpenAI/Codex/IntegrityMemoryLTS/ClaudeDesktopNative/native-event-factory.py")
        captured=path.read_bytes()
        if path.is_symlink() or hashlib.sha256(captured).hexdigest()!='0000000000000000000000000000000000000000000000000000000000000001':raise HookError("claude_desktop_launcher_changed")
        factory=ModuleType("claude_desktop_protected_launcher");factory.__file__=str(path)
        exec(compile(captured,str(path),"exec"),factory.__dict__)
        return factory.load(mode="hook").run_own_hook(payload,args.event)
    if identity=='00000000-0000-4000-8000-000000000002':
        from types import ModuleType
        path=Path('~\\.claude\\integrity-memory\\dispatch-generations\\0000000000000000000000000000000000000000000000000000000000000002\\claude_native_dispatch.py')
        raw=path.read_bytes()
        if path.is_symlink() or hashlib.sha256(raw).hexdigest()!='0000000000000000000000000000000000000000000000000000000000000002':raise HookError("claude_native_dispatch_changed")
        module=ModuleType("claude_hook_native_dispatch");module.__file__=str(path)
        exec(compile(raw,str(path),"exec"),module.__dict__)
        return module.run_hook(payload)
    if identity == '00000000-0000-4000-8000-000000000002' and Path('~/.claude/integrity-memory/delegation-config.json').exists():
        try:
            with session_state_lock(identity):
                if _claude_receiving_factory().run(args.event, payload, sys.modules[__name__]):
                    return 0
        except Exception:
            if args.event == 'PreToolUse':
                deny('Claude delegated origin/binding infrastructure denied')
            raise HookError('claude_receiving_infrastructure_failed') from None
    if args.event == "SessionStart":
        notice = degraded_health_notice()
        output_context(
            args.event,
            (notice + "\n" if notice else "")
            + "INTEGRITY client SESSION PENDING INTENT ADMISSION. No Seed snapshot was opened at startup.",
        )
        return 0
    if args.event in {"SubagentStart", "SubagentStop"} or (
        args.event == "Stop" and subagent_id(payload) is not None
    ):
        # ISS-049: these carry the parent's session_id. Run as before they restaged the parent's
        # envelope (SubagentStart -> handle_prompt) or ran the parent's Stop guard and declined-close
        # bookkeeping on a subagent's finish (SubagentStop -> handle_stop). Neither is the parent's.
        return 0
    with session_state_lock(identity):
        if args.event in {"UserPromptSubmit", "SubagentStart"}:
            handle_prompt(args.event, payload, identity)
            return 0
        state = load_state(identity)
        if args.event == "PreToolUse":
            handle_pre_tool(payload, identity, state)
        elif args.event == "PostToolUse":
            handle_post_tool(args.event, payload, identity, state)
        elif args.event == "PostToolUseFailure":
            handle_post_tool_failure(args.event, payload, identity, state)
        else:
            handle_stop(args.event, identity, state, payload)
    return 0


def invoked_event(argv: list[str]) -> str:
    for index, value in enumerate(argv):
        if value == "--event" and index + 1 < len(argv):
            return argv[index + 1]
        if value.startswith("--event="):
            return value.split("=", 1)[1]
    return ""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HookError as exc:
        print(f"Integrity hook infrastructure fault: {exc}", file=sys.stderr)
        if invoked_event(sys.argv[1:]) == "UserPromptSubmit":
            # A memory fault must not drop the owner's message (exit 2 blocks it).
            # Fail open with an explicit notice: no turn_ref, no admission, no OPEN;
            # tool and append guards keep failing closed in their own events.
            output_context(
                "UserPromptSubmit",
                f"INTEGRITY MEMORY NOT DELIVERED: hook infrastructure fault {exc}. The owner "
                "message was passed through without Integrity memory; no turn_ref was issued "
                "for this intent, so context admission is unavailable. Tell the owner.",
            )
            raise SystemExit(0)
        raise SystemExit(2)
