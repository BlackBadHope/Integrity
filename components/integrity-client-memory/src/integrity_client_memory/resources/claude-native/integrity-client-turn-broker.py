# SPDX-License-Identifier: BUSL-1.1
"""Lazy MCP broker that retains one upstream transport for logical contexts."""
from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import tomllib
from pathlib import Path
from typing import Any
import integrity_client_turn_envelope as turn_envelope
import types as _compact_types
_compact_admission = _compact_types.ModuleType("integrity_compact_admission")
exec(compile('# SPDX-License-Identifier: BUSL-1.1\n"""File-backed admission presentation; never change canonical admission or receipts."""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\n\nimport copy\nimport hashlib\nimport json\nimport os\nimport re\nimport stat\nimport tempfile\nfrom pathlib import Path\n\nPROTOCOL = \'integrity-admission-compact/v1\'\nMAX_ARTIFACT = 16 * 1024 * 1024\nMAX_PUBLIC = 8192\nSHA = re.compile(r\'[0-9a-f]{64}\\Z\')\n\n\ndef encode(value):\n    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(\',\', \':\')).encode(\'utf-8\')\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n\n\ndef default_root():\n    # This source revision targets the owner-host Codex and Claude clients together.\n    # No public tool argument or environment override can redirect file reads.\n    return Path.home() / \'.codex\' / \'integrity-memory\' / \'admission-artifacts\'\n\n\ndef safe_chain(path):\n    for item in (*reversed(path.parents), path):\n        s = item.lstat()\n        if stat.S_ISLNK(s.st_mode) or getattr(s, \'st_file_attributes\', 0) & 0x400:\n            raise ValueError(\'artifact_link_refused\')\n\n\ndef read_file(root, hexdigest):\n    if not isinstance(hexdigest, str) or not SHA.fullmatch(hexdigest):\n        raise ValueError(\'artifact_digest_invalid\')\n    root = Path(root).absolute()\n    safe_chain(root)\n    path = root / (hexdigest + \'.json\')\n    safe_chain(path)\n    flags = os.O_RDONLY | getattr(os, \'O_BINARY\', 0) | getattr(os, \'O_NOFOLLOW\', 0)\n    fd = os.open(path, flags)\n    with os.fdopen(fd, \'rb\') as stream:\n        before = os.fstat(stream.fileno())\n        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT:\n            raise ValueError(\'artifact_file_invalid\')\n        data = stream.read(MAX_ARTIFACT + 1)\n        after = os.fstat(stream.fileno())\n    if (len(data) > MAX_ARTIFACT or before.st_size != after.st_size\n            or before.st_mtime_ns != after.st_mtime_ns or digest(data) != hexdigest):\n        raise ValueError(\'artifact_digest_mismatch\')\n    return data\n\n\ndef store_file(root, data):\n    if len(data) > MAX_ARTIFACT:\n        raise ValueError(\'artifact_too_large\')\n    root = Path(root).absolute()\n    # Validate existing ancestors before mkdir; validate the complete chain after.\n    existing = root\n    while not existing.exists():\n        existing = existing.parent\n    safe_chain(existing)\n    root.mkdir(parents=True, exist_ok=True, mode=0o700)\n    safe_chain(root)\n    hexdigest = digest(data)\n    path = root / (hexdigest + \'.json\')\n    if path.exists():\n        if read_file(root, hexdigest) != data:\n            raise ValueError(\'artifact_collision\')\n        return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n    fd, temporary_name = tempfile.mkstemp(prefix=\'.admission-\', suffix=\'.tmp\', dir=root)\n    temporary = Path(temporary_name)\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        # Atomic no-clobber publication. A failed/terminated write cannot leave\n        # incomplete bytes under the final digest name. NTFS supports hard links.\n        try:\n            os.link(temporary, path)\n        except FileExistsError:\n            if read_file(root, hexdigest) != data:\n                raise ValueError(\'artifact_collision\')\n        except PermissionError:\n            # Android app sandboxes (DroidDeck proot) deny hard links. The name is\n            # the content digest, so publishing complete bytes cannot clobber\n            # different content; the readback below still verifies them.\n            os.replace(temporary, path)\n    finally:\n        temporary.unlink(missing_ok=True)\n    if read_file(root, hexdigest) != data:\n        raise ValueError(\'artifact_readback_mismatch\')\n    return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n\n\ndef admission_document(result):\n    if not isinstance(result, dict) or result.get(\'isError\') is True:\n        return None\n    content = result.get(\'content\')\n    if not isinstance(content, list) or len(content) != 1:\n        return None\n    block = content[0]\n    if not isinstance(block, dict) or block.get(\'type\') != \'text\':\n        return None\n    try:\n        doc = json.loads(block[\'text\'])\n    except (KeyError, ValueError, TypeError):\n        return None\n    if not isinstance(doc, dict) or doc.get(\'protocol\') not in {\n        \'integrity-client-memory-mcp/v3/context-admission/v1\',\n        \'integrity-client-memory-mcp/v3/context-admission/v2\',\n    }:\n        return None\n    return doc\n\n\ndef resolve_wrapper(wrapper, root=None):\n    if not isinstance(wrapper, dict) or wrapper.get(\'protocol\') != PROTOCOL:\n        return wrapper\n    artifact = wrapper.get(\'full_admission\')\n    if not isinstance(artifact, dict):\n        raise ValueError(\'artifact_reference_missing\')\n    # The path is explanatory only; read only the pinned root + digest name.\n    trusted = default_root() if root is None else Path(root)\n    if artifact.get(\'path\') != str(trusted.absolute() / (str(artifact.get(\'sha256\')) + \'.json\')):\n        raise ValueError(\'artifact_path_mismatch\')\n    raw = read_file(trusted, artifact.get(\'sha256\'))\n    if artifact.get(\'bytes\') != len(raw):\n        raise ValueError(\'artifact_size_mismatch\')\n    result = json.loads(raw)\n    doc = admission_document(result)\n    if doc is None:\n        raise ValueError(\'artifact_not_admission\')\n    if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n        raise ValueError(\'artifact_document_shape_invalid\')\n    binding = wrapper.get(\'admission\')\n    expected = {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\'),\n                \'status\': doc.get(\'status\')}\n    if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in expected.items()):\n        raise ValueError(\'artifact_admission_binding_mismatch\')\n    # The hook still runs its original prompt/snapshot/receipt validation on doc.\n    return doc\n\n\ndef _public_result(wrapper):\n    return {\'content\': [{\'type\': \'text\', \'text\': encode(wrapper).decode(\'utf-8\')}], \'isError\': False}\n\n\ndef public_size(wrapper):\n    return len(encode(_public_result(wrapper)))\n\n\ndef _clip(text, byte_limit):\n    return text.encode(\'utf-8\')[:max(0, byte_limit)].decode(\'utf-8\', errors=\'ignore\')\n\n\nclass Presenter:\n    def __init__(self, root=None):\n        self.root = default_root() if root is None else Path(root)\n        self.capabilities_sha256 = None\n        self.capabilities_by_context = {}\n\n    def present(self, result, *, context_key=None):\n        try:\n            doc = admission_document(result)\n            if doc is None:\n                return result\n            return self._present(result, doc, context_key)\n        except Exception as exc:\n            # Admission may already have succeeded. Do not turn that success into\n            # a retry or hide its identity: retain the original response and mark\n            # presentation degraded. The strict byte bound is explicitly unmet.\n            fault = {\n                \'protocol\': \'integrity-compact-presentation-fault/v1\',\n                \'status\': \'degraded\', \'reason\': type(exc).__name__,\n                \'notify_owner_required\': True, \'byte_budget_met\': False,\n                \'admission_repeated\': False,\n            }\n            # The original admission JSON itself remains byte-identical, so no\n            # top-level field can accidentally enter a signed/digested document.\n            return {**result, \'content\': [{\'type\': \'text\', \'text\': encode(fault).decode(\'utf-8\')},\n                                         *result.get(\'content\', [])]}\n\n    def _present(self, result, doc, context_key):\n        if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n            raise ValueError(\'artifact_document_shape_invalid\')\n        ref = store_file(self.root, encode(result))\n        mind = doc.get(\'mind\', {})\n        capsule = mind.get(\'mind\', {}) if isinstance(mind, dict) else {}\n        if not isinstance(capsule, dict):\n            capsule = {}\n        crc = doc.get(\'canonical_read_context\') or mind.get(\'canonical_read_context\') or {}\n        if not isinstance(crc, dict):\n            crc = {}\n        events = crc.get(\'events\', [])\n        if not isinstance(events, list):\n            events = []\n        ids = crc.get(\'event_ids\') or [e.get(\'event_id\', e.get(\'id\')) for e in events if isinstance(e, dict)]\n        if not isinstance(ids, list):\n            ids = []\n        text = doc.get(\'context_text\') or capsule.get(\'context_text\') or \'\'\n        if not isinstance(text, str):\n            text = \'\'\n        synaptic = capsule.get(\'synaptic\', {})\n        if not isinstance(synaptic, dict):\n            synaptic = {}\n        selection = mind.get(\'selection_receipt\', {})\n        if not isinstance(selection, dict):\n            selection = {}\n        if not text:\n            topic = crc.get(\'topic\') or \'события \' + \', \'.join(str(x) for x in ids)\n            text = \'Тема: \' + str(topic) + \'\\n\' + encode({\n                \'door\': synaptic.get(\'door\'),\n                \'selected_candidates\': selection.get(\'selected_candidates\'),\n                \'canonical_event_ids\': ids,\n            }).decode(\'utf-8\')\n            text += \'\\nSelected: \' + encode(capsule.get(\'working_set\', {})).decode(\'utf-8\')\n            text += \'\\nSynaptic: \' + encode({key: synaptic.get(key)\n                for key in (\'here\', \'links\', \'moves\', \'learned_hints\')}).decode(\'utf-8\')\n        delivery = doc.get(\'context_delivery\') or capsule.get(\'context_delivery\') or {}\n        capabilities = doc.get(\'capabilities\')\n        cap_sha = digest(encode(capabilities))\n        previous = self.capabilities_by_context.get(context_key) if context_key is not None else None\n        cap_change = \'first\' if previous is None else (\n            \'unchanged\' if cap_sha == previous else \'changed\')\n        wrapper = {\n            \'protocol\': PROTOCOL, \'full_admission\': ref,\n            \'context_text\': \'\', \'context_delivery\': delivery,\n            \'admission\': {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                          \'status\': doc.get(\'status\'), \'health\': doc.get(\'health\'),\n                          \'door\': synaptic.get(\'door\'),\n                          \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\')},\n            \'selected\': selection.get(\'selected_candidates\'),\n            \'canonical_read_context\': {\'event_ids\': ids, \'events\': [],\n                \'admission_json_string_in_full_result\': \'/content/0/text\',\n                \'events_pointer_in_parsed_admission\': (\'/canonical_read_context/events\'\n                    if doc.get(\'canonical_read_context\') else \'/mind/canonical_read_context/events\')},\n            \'presentation\': {\'byte_limit\': MAX_PUBLIC, \'status\': \'file-backed\',\n                             \'context_text_truncated\': False, \'deferred_exact_event_ids\': [],\n                             \'deferred_events\': []},\n            \'capabilities_ref\': {\'sha256\': cap_sha, \'status\': cap_change,\n                                 \'cache_scope\': \'verified-thread\' if context_key is not None else \'disabled-unbound\',\n                                 \'json_pointer_in_admission\': \'/capabilities\'},\n        }\n        # Reserve space for an owner-visible topic/context excerpt first.\n        wrapper[\'context_text\'] = _clip(text, 1024)\n        deferred = []\n        for index, event in enumerate(events):\n            trial = copy.deepcopy(wrapper)\n            trial[\'canonical_read_context\'][\'events\'].append(event)\n            # Keep space for diagnostics, deferred IDs, and capabilities summary.\n            if public_size(trial) <= MAX_PUBLIC - 1200:\n                wrapper = trial\n            else:\n                event_id = event.get(\'event_id\', event.get(\'id\')) if isinstance(event, dict) else None\n                if event_id is not None:\n                    deferred.append(event_id)\n                row = {\'index\': index, \'sha256\': digest(encode(event))}\n                if event_id is not None:\n                    row[\'event_id\'] = event_id\n                wrapper[\'presentation\'][\'deferred_events\'].append(row)\n        wrapper[\'presentation\'][\'deferred_exact_event_ids\'] = deferred\n        if cap_change != \'unchanged\':\n            trial = {**wrapper, \'capabilities\': capabilities}\n            if public_size(trial) <= MAX_PUBLIC - 512:\n                wrapper = trial\n            else:\n                wrapper[\'capabilities_ref\'][\'status\'] = cap_change + \'_deferred\'\n        current_text = wrapper[\'context_text\']\n        remaining = MAX_PUBLIC - public_size(wrapper) - 32\n        if remaining > 0 and current_text != text:\n            trial = {**wrapper, \'context_text\': _clip(text, len(current_text.encode(\'utf-8\')) + remaining // 2)}\n            while public_size(trial) > MAX_PUBLIC:\n                trial[\'context_text\'] = _clip(trial[\'context_text\'], len(trial[\'context_text\'].encode(\'utf-8\')) // 2)\n            wrapper = trial\n        wrapper[\'presentation\'][\'context_text_truncated\'] = wrapper[\'context_text\'] != text\n        if public_size(wrapper) > MAX_PUBLIC:\n            raise ValueError(\'compact_metadata_exceeds_byte_budget\')\n        # Commit advertisement state only after successful serialization/storage.\n        if \'capabilities\' in wrapper:\n            self.capabilities_sha256 = cap_sha\n            if context_key is not None:\n                self.capabilities_by_context[context_key] = cap_sha\n        return _public_result(wrapper)\n', "frozen-compact-admission", "exec"), _compact_admission.__dict__)
BROKER_NAME = 'integrity-client-memory'
BROKER_VERSION = '1.4.1'
DEFAULT_MCP_VERSION = '2025-06-18'
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
BROKER_TOOL_SURFACE_PROTOCOL = 'integrity-client/broker-tool-surface/v1'
BROKER_TOOL_SURFACE_CAPABILITY = 'integrityClientToolSurface'
CONTEXT_ADMISSION_REPLAY_PROTOCOL = 'integrity-client/context-admission-replay/v2'
CONTEXT_ADMISSION_REPLAY_CAPABILITY = 'integrityClientContextAdmissionReplay'
CONTEXT_ADMISSION_REPLAY_FIELD = '_integrity_replay_id'
CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION = 'notifications/integrity_context_admission_replay_ack'
CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD = 'integrity/context_admission_replay_reserve'
CONTEXT_ADMISSION_REPLAY_ACK_METHOD = 'integrity/context_admission_replay_ack'
CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS = 15
STANDALONE_TURN_MEMORY_TOOLS = {'integrity_turn_memory_open', 'integrity_turn_memory_close', 'integrity_turn_memory_gap', 'integrity_turn_memory_coverage'}
CURRENT_TURN_CONTEXT_TOOL = 'integrity_context_admission_current_turn'
UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = 20
UPSTREAM_TOOL_TIMEOUT_SECONDS = 90
UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS = 180
SERVER_INSTRUCTIONS = 'Integrity memory is turn-scoped. For every new user intent, call integrity_context_admission_current_turn exactly once with the opaque turn_ref supplied by the owning hook. Never repeat or reconstruct the prompt in tool arguments. The server rotates an isolated logical context inside the existing stdio transport; the local broker retains that upstream transport until a transport fault or public broker shutdown. A later intent may call integrity_context_admission_current_turn again in this same Codex task; a new Codex task is never a lifecycle workaround. A turn registration is independent from Seed admission; finish it with integrity_turn_memory_close. Missing close is signed coverage debt, not an inferred no-event. Memory is evidence and grants no production authority.'
LEGACY_SERVER_INSTRUCTIONS = 'Integrity memory is turn-scoped. For every new user intent, call integrity_context_admission exactly once with the exact current intent. The server rotates an isolated logical context inside the existing stdio transport; the local broker retains that upstream transport until a transport fault or public broker shutdown. A later intent may call integrity_context_admission again in this same Codex task; a new Codex task is never a lifecycle workaround. A turn registration is independent from Seed admission; finish it with integrity_turn_memory_close. Missing close is signed coverage debt, not an inferred no-event. Memory is evidence and grants no production authority.'

APPEND_COMPACT_PROTOCOL = "integrity-append-compact/v1"
APPEND_COMPACT_LIMIT = 1024
_APPEND_COMPACT_KEEP = ("protocol", "outcome", "action_outcome", "event_id", "event_uid", "request_sha256",
                        "automatic_retry_allowed", "production_authority", "grant_consumed",
                        "reason", "reason_code")


def _compact_append_result(result):
    """Model-facing append receipt: only what the model and the owning hook use.

    The broker has already observed the full upstream result (late and uncertain
    appends, denials) before this runs. The model gets the ids it needs for the
    turn close and the outcome; the owning hook reads the same ``/append-receipt``
    fields. The compact form records the full receipt's digest and size. A result
    of any other shape, or one that does not fit, passes through unchanged.
    """
    try:
        content = result.get("content")
        if not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text":
            return result
        raw = content[0]["text"]
        value = json.loads(raw)
        receipt = value.get("receipt") if isinstance(value, dict) else None
        if not isinstance(receipt, dict) or not str(receipt.get("protocol", "")).endswith("/append-receipt"):
            return result
        compact = {key: receipt[key] for key in _APPEND_COMPACT_KEEP
                   if key in receipt and isinstance(receipt[key], (str, int, bool, type(None)))}
        witness = receipt.get("passive_witness")
        if isinstance(witness, dict) and isinstance(witness.get("status"), str):
            compact["witness_status"] = witness["status"]
        compact["compaction"] = {"protocol": APPEND_COMPACT_PROTOCOL,
                                 "full_receipt_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                                 "full_bytes": len(raw.encode("utf-8"))}
        text = json.dumps({"receipt": compact}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(text.encode("utf-8")) > APPEND_COMPACT_LIMIT:
            return result
        out = {key: item for key, item in result.items() if key != "structuredContent"}
        out["content"] = [{"type": "text", "text": text}]
        if "structuredContent" in result:
            out["structuredContent"] = {"receipt": compact}
        return out
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return result


class BrokerError(RuntimeError):
    """A fail-closed local broker or upstream transport failure."""

    def __init__(self, message: str, *, layer: str, request_sent: bool=False, retryable: bool=False) -> None:
        super().__init__(message)
        self.layer = layer
        self.request_sent = request_sent
        self.retryable = retryable

def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _load_tools_contract(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError('tools contract is unavailable', layer='broker-config') from exc
    if not isinstance(value, list) or not value:
        raise BrokerError('tools contract is invalid', layer='broker-config')
    names: list[str] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or (not isinstance(item.get('description'), str)) or (not isinstance(item.get('inputSchema'), dict)) or (not isinstance(item.get('annotations'), dict)):
            raise BrokerError('tools contract entry is invalid', layer='broker-config')
        names.append(item['name'])
    if len(names) != len(set(names)) or 'integrity_context_admission' not in names:
        raise BrokerError('tools contract names are invalid', layer='broker-config')
    return value

def _tool_surface(value: list[dict[str, Any]]) -> bytes:
    if not all((isinstance(item, dict) for item in value)):
        raise BrokerError('upstream tool contract changed', layer='broker-upstream')
    return _json_bytes([{'name': item.get('name'), 'inputSchema': item.get('inputSchema'), 'annotations': item.get('annotations')} for item in value])

def _tool_surface_sha256(value: list[dict[str, Any]]) -> str:
    return 'sha256:' + hashlib.sha256(_tool_surface(value)).hexdigest()

def _surface_acknowledged(initialized: dict[str, Any], expected_sha256: str) -> bool:
    capabilities = initialized.get('capabilities')
    experimental = capabilities.get('experimental') if isinstance(capabilities, dict) else None
    acknowledgement = experimental.get(BROKER_TOOL_SURFACE_CAPABILITY) if isinstance(experimental, dict) else None
    return bool(isinstance(acknowledgement, dict) and acknowledgement.get('protocol') == BROKER_TOOL_SURFACE_PROTOCOL and (acknowledgement.get('accepted_tools_surface_sha256') == expected_sha256) and (acknowledgement.get('compatibility') == 'local-contract-facade-with-upstream-name-subset/v1'))

def _context_admission_replay_acknowledgement(initialized: dict[str, Any], reservation_id: str | None) -> dict[str, Any] | None:
    capabilities = initialized.get('capabilities')
    experimental = capabilities.get('experimental') if isinstance(capabilities, dict) else None
    acknowledgement = experimental.get(CONTEXT_ADMISSION_REPLAY_CAPABILITY) if isinstance(experimental, dict) else None
    if not (isinstance(acknowledgement, dict) and acknowledgement.get('protocol') == CONTEXT_ADMISSION_REPLAY_PROTOCOL and (acknowledgement.get('request_identity_field') == CONTEXT_ADMISSION_REPLAY_FIELD) and (acknowledgement.get('request_identity_format') == 'sha256/v1') and (reservation_id is not None) and (acknowledgement.get('reservation_id') == reservation_id) and (acknowledgement.get('reservation_method') == CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD) and (acknowledgement.get('ack_method') == CONTEXT_ADMISSION_REPLAY_ACK_METHOD) and (acknowledgement.get('durability') == 'architecture-custody-root/v1') and (acknowledgement.get('replay_semantics') == 'exact-response/v1') and (acknowledgement.get('max_transport_retries') == 1) and (acknowledgement.get('reservation_status') in {None, 'reserved', 'unavailable'})):
        return None
    return acknowledgement

def _upstream_supports_local_tools(upstream_tools: list[dict[str, Any]], tools_contract: list[dict[str, Any]]) -> bool:
    """Require every broker-exposed contract to remain byte-structurally callable.

    An acknowledgement permits additive upstream tools; it never permits a
    same-name schema or annotation change.  Comparing only names let an
    upstream release acknowledge a retained digest while silently breaking
    the installed broker's arguments contract.
    """
    if not all((isinstance(item, dict) for item in upstream_tools)):
        return False
    upstream_names = [item.get('name') for item in upstream_tools]
    if not all((isinstance(name, str) and name for name in upstream_names)):
        return False
    upstream_by_name = dict(zip(upstream_names, upstream_tools, strict=True))
    if len(upstream_by_name) != len(upstream_tools):
        return False
    for local in tools_contract:
        upstream = upstream_by_name.get(local['name'])
        if upstream is None or any((upstream.get(field) != local.get(field) for field in ('inputSchema', 'annotations'))):
            return False
    return True

def _load_upstream(config_path: Path, server_name: str) -> tuple[list[str], dict[str, str], str | None]:
    try:
        with config_path.open('rb') as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BrokerError('Codex MCP config is unavailable', layer='broker-config') from exc
    servers = config.get('mcp_servers')
    server = servers.get(server_name) if isinstance(servers, dict) else None
    if not isinstance(server, dict):
        raise BrokerError('internal upstream registration is missing', layer='broker-config')
    if server.get('enabled') is not False:
        raise BrokerError('internal upstream must be disabled for Codex', layer='broker-config')
    command = server.get('command')
    arguments = server.get('args', [])
    configured_env = server.get('env')
    cwd = server.get('cwd')
    if not isinstance(command, str) or not command.strip():
        raise BrokerError('internal upstream command is invalid', layer='broker-config')
    if not isinstance(arguments, list) or not all((isinstance(item, str) for item in arguments)):
        raise BrokerError('internal upstream arguments are invalid', layer='broker-config')
    if configured_env is None:
        configured_env = {}
    if not isinstance(configured_env, dict) or not all((isinstance(key, str) and isinstance(value, str) for key, value in configured_env.items())):
        raise BrokerError('internal upstream environment is invalid', layer='broker-config')
    if cwd is not None and (not isinstance(cwd, str)):
        raise BrokerError('internal upstream working directory is invalid', layer='broker-config')
    environment = dict(os.environ)
    environment.update(configured_env)
    return ([command, *arguments], environment, cwd)

class UpstreamFacade:
    """One initialized upstream stdio process shared by sequential logical contexts."""

    def __init__(self, command: list[str], environment: dict[str, str], cwd: str | None, tools_contract: list[dict[str, Any]], initialize_params: dict[str, Any], context_replay_reservation_id: str | None=None) -> None:
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._next_id = 1000000000
        self.context_admission_replay_safe = False
        self.context_admission_replay_contract_safe = False
        self.context_admission_replay_ack_request_safe = False
        self._context_replay_reservation_id = context_replay_reservation_id
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=environment, cwd=cwd, bufsize=0)
        except OSError as exc:
            raise BrokerError('upstream process could not start', layer='broker-upstream', retryable=True) from exc
        assert self.process.stdin is not None and self.process.stdout is not None
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        try:
            params = dict(initialize_params)
            tools_surface_sha256 = _tool_surface_sha256(tools_contract)
            capabilities = params.get('capabilities')
            capabilities = dict(capabilities) if isinstance(capabilities, dict) else {}
            experimental = capabilities.get('experimental')
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            experimental[BROKER_TOOL_SURFACE_CAPABILITY] = {'protocol': BROKER_TOOL_SURFACE_PROTOCOL, 'tools_surface_sha256': tools_surface_sha256}
            experimental[CONTEXT_ADMISSION_REPLAY_CAPABILITY] = {'protocol': CONTEXT_ADMISSION_REPLAY_PROTOCOL, 'request_identity_field': CONTEXT_ADMISSION_REPLAY_FIELD, 'request_identity_format': 'sha256/v1', **({'reservation_id': context_replay_reservation_id} if context_replay_reservation_id is not None else {})}
            capabilities['experimental'] = experimental
            params['capabilities'] = capabilities
            params['clientInfo'] = {'name': 'integrity-client-turn-broker', 'version': BROKER_VERSION}
            initialized = self.request('initialize', params, timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS)
            server_info = initialized.get('serverInfo')
            if not isinstance(server_info, dict) or server_info.get('name') != BROKER_NAME:
                raise BrokerError('upstream identity mismatch', layer='broker-upstream')
            replay_acknowledgement = _context_admission_replay_acknowledgement(initialized, context_replay_reservation_id)
            self.context_admission_replay_contract_safe = replay_acknowledgement is not None
            self.context_admission_replay_safe = bool(replay_acknowledgement is not None and replay_acknowledgement.get('reservation_status') != 'unavailable')
            self.context_admission_replay_ack_request_safe = self.context_admission_replay_contract_safe
            self.notify('notifications/initialized', {})
            listed = self.request('tools/list', {}, timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS)
            upstream_tools = listed.get('tools')
            acknowledged = _surface_acknowledged(initialized, tools_surface_sha256)
            if not isinstance(upstream_tools, list) or (acknowledged and (not _upstream_supports_local_tools(upstream_tools, tools_contract))) or (not acknowledged and _tool_surface(upstream_tools) != _tool_surface(tools_contract)):
                raise BrokerError('upstream tool contract changed', layer='broker-upstream')
        except BaseException:
            if self.context_admission_replay_ack_request_safe and self._context_replay_reservation_id is not None:
                empty_digest = 'sha256:' + hashlib.sha256(_json_bytes({})).hexdigest()
                try:
                    self.acknowledge_context_admission_replay({'replay_id': self._context_replay_reservation_id, 'request_digest': empty_digest, 'response_digest': empty_digest})
                except BrokerError:
                    pass
            self.close()
            raise

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                raw = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not raw:
                    break
                self._responses.put(raw)
        finally:
            self._responses.put(None)

    def _write(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        payload = _json_bytes(message)
        if len(payload) > MAX_MESSAGE_BYTES:
            raise BrokerError('upstream request exceeds limit', layer='broker-upstream')
        wire_payload = payload + b'\n'
        written_total = 0
        try:
            while written_total < len(wire_payload):
                written = self.process.stdin.write(memoryview(wire_payload)[written_total:])
                if not isinstance(written, int) or isinstance(written, bool) or written <= 0 or (written > len(wire_payload) - written_total):
                    raise OSError('upstream request transport made no progress')
                written_total += written
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BrokerError('upstream request transport failed', layer='broker-upstream', request_sent=written_total > 0, retryable=True) from exc

    MAX_LATE_RESPONSES = 8

    def _receive(self, request_id: Any, *, timeout: int, request_sent: bool) -> dict[str, Any]:
        import time
        deadline = time.monotonic() + timeout
        while True:
            try:
                raw = self._responses.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise BrokerError('upstream response timed out', layer='broker-upstream', request_sent=request_sent, retryable=True) from exc
            if raw is None:
                raise BrokerError('upstream closed its response stream', layer='broker-upstream', request_sent=request_sent, retryable=True)
            if len(raw) > MAX_MESSAGE_BYTES:
                raise BrokerError('upstream response exceeds limit', layer='broker-upstream', request_sent=request_sent, retryable=True)
            try:
                response = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrokerError('upstream returned invalid JSON', layer='broker-upstream', request_sent=request_sent, retryable=True) from exc
            late = getattr(self, '_late_request_ids', set())
            if isinstance(response, dict) and response.get('id') != request_id and response.get('id') in late:
                # The reply to an earlier request that timed out after it was sent
                # (option 4 warm lifecycle). Drop it; the admitted stream stays usable.
                late.discard(response.get('id'))
                continue
            break
        if not isinstance(response, dict) or response.get('id') != request_id:
            raise BrokerError('upstream response id mismatch', layer='broker-upstream', request_sent=request_sent, retryable=True)
        if response.get('error') is not None:
            raise BrokerError('upstream rejected the MCP request', layer='broker-upstream', request_sent=request_sent)
        result = response.get('result')
        if not isinstance(result, dict):
            raise BrokerError('upstream result is invalid', layer='broker-upstream', request_sent=request_sent)
        return result

    def request(self, method: str, params: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._write({'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        try:
            return self._receive(request_id, timeout=timeout, request_sent=True)
        except BrokerError as error:
            if str(error) == 'upstream response timed out':
                late = getattr(self, '_late_request_ids', set())
                if len(late) < self.MAX_LATE_RESPONSES:
                    late.add(request_id)
                    self._late_request_ids = late
            raise

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request('tools/call', {'name': name, 'arguments': arguments}, timeout=UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS if name == 'integrity_context_admission' else UPSTREAM_TOOL_TIMEOUT_SECONDS)

    def reserve_context_admission_replay(self, reservation_id: str) -> bool:
        if not self.context_admission_replay_contract_safe:
            return False
        try:
            result = self.request(CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD, {'reservation_id': reservation_id}, timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS)
        except BrokerError as exc:
            if exc.retryable:
                raise
            return False
        reserved = bool(result.get('protocol') == 'integrity-client/context-admission-replay-reservation/v1' and result.get('reservation_id') == reservation_id and (result.get('reserved') is True))
        if reserved:
            self.context_admission_replay_safe = True
            self.context_admission_replay_ack_request_safe = True
        return reserved

    def acknowledge_context_admission_replay(self, acknowledgement: dict[str, str]) -> bool:
        result = self.request(CONTEXT_ADMISSION_REPLAY_ACK_METHOD, acknowledgement, timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS)
        return bool(result.get('protocol') == 'integrity-client/context-admission-replay-reservation/v1' and result.get('replay_id') == acknowledgement.get('replay_id') and (result.get('retired') is True))

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({'jsonrpc': '2.0', 'method': method, 'params': params})

    def close(self) -> None:
        process = getattr(self, 'process', None)
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None or stream.closed:
                continue
            try:
                stream.close()
            except OSError:
                pass
        reader = getattr(self, '_reader', None)
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=2)
        self.process = None

class TurnBroker:
    """Local MCP surface with one lazy upstream and server-owned context rotation."""

    def __init__(self, config_path: Path, upstream_server: str, tools_contract: list[dict[str, Any]]) -> None:
        self.config_path = config_path
        self.upstream_server = upstream_server
        self.tools_contract = tools_contract
        self.tool_names = {item['name'] for item in tools_contract}
        self.initialize_params: dict[str, Any] = {'protocolVersion': DEFAULT_MCP_VERSION, 'capabilities': {}, 'clientInfo': {'name': 'unknown-client', 'version': '0'}}
        self.upstream: UpstreamFacade | None = None
        self.bound = False
        self._own_turn_binding = None
        self._owning_hook_lifecycle_ref = os.environ.get('INTEGRITY_OWNING_LIFECYCLE_REF')
        self._binding_loss_receipt_digest: str | None = None
        self._uncertain_append_receipt_digest: str | None = None
        self._last_cleanup_failure_type: str | None = None
        self._pending_context_replay_acks: list[dict[str, str]] = []
        self._context_replay_acks_awaiting_public_delivery: set[str] = set()
        self._turn_envelopes_awaiting_public_delivery: list[tuple[str, str]] = []

    def close(self) -> None:
        upstream = self.upstream
        self.upstream = None
        self.bound = False
        if upstream is not None:
            upstream.close()

    def _observe_upstream_denial(self, name: str, result: dict[str, Any]) -> None:
        """Invalidate local beliefs only; never replay, restore or replace an error."""
        if result.get('isError') is not True and name != 'integrity_append_event':
            return
        content = result.get('content')
        if not isinstance(content, list):
            return
        for item in content:
            if not isinstance(item, dict) or item.get('type') != 'text':
                continue
            raw = item.get('text')
            if not isinstance(raw, str) or len(raw) > MAX_MESSAGE_BYTES:
                continue
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if not isinstance(value, dict):
                continue
            receipt = value.get('receipt', value)
            if not isinstance(receipt, dict):
                continue
            outcome = receipt.get('outcome')
            action_outcome = receipt.get('action_outcome')
            reason = receipt.get('reason')
            lost = result.get('isError') is True and outcome == 'denied' and (receipt.get('failure_layer') == 'context-binding' and receipt.get('context_binding_state') == 'empty' or (isinstance(reason, str) and reason in {'append context binding DENY: current logical context is empty', 'append context binding DENY: no composite context admission is active'}))
            uncertain = name == 'integrity_append_event' and any((isinstance(candidate, str) and candidate in {'unknown', 'unknown-outcome'} for candidate in (outcome, action_outcome)))
            if not lost and (not uncertain):
                continue
            reference_fields = {key: value for key, value in receipt.items() if key in {'protocol', 'tool', 'outcome', 'action_outcome', 'reason', 'reason_code', 'arguments_digest', 'context_binding_state', 'logical_generation'} and isinstance(value, (str, int, bool))}
            reference = 'sha256:' + hashlib.sha256(json.dumps(reference_fields, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
            if lost:
                self.bound = False
                self._binding_loss_receipt_digest = reference
            if uncertain:
                self._uncertain_append_receipt_digest = reference

    def _new_upstream(self, context_replay_reservation_id: str | None=None) -> UpstreamFacade:
        command, environment, cwd = _load_upstream(self.config_path, self.upstream_server)
        return UpstreamFacade(command, environment, cwd, self.tools_contract, self.initialize_params, context_replay_reservation_id)

    def _open_upstream(self, context_replay_reservation_id: str | None=None) -> None:
        self.close()
        self.upstream = self._new_upstream(context_replay_reservation_id)

    def _denial(self, name: str, exc: BrokerError) -> dict[str, Any]:
        write_outcome_unknown = name == 'integrity_append_event' and exc.request_sent
        safe_current_turn_retry = name == CURRENT_TURN_CONTEXT_TOOL and (not exc.request_sent) and (exc.layer == 'broker-upstream')
        value = {'protocol': 'integrity-client/turn-broker-denial/v1', 'outcome': 'unknown' if write_outcome_unknown else 'denied', 'failure_layer': exc.layer, 'tool': name, 'reason': str(exc)[:500], 'request_sent': exc.request_sent, 'automatic_retry_allowed': safe_current_turn_retry, 'canonical_writes': 'unknown' if write_outcome_unknown else 0, 'production_authority': False}
        if safe_current_turn_retry:
            value['retry_disposition'] = 'exact-envelope-after-pre-send-transport'
        if exc.layer == 'broker-context-lost':
            value['primary_denial_reference'] = self._binding_loss_receipt_digest
            value['coverage_disposition'] = 'preserve-registration-and-gap'
        if exc.layer == 'broker-append-uncertain':
            value['prior_canonical_write_outcome'] = 'unknown'
            value['primary_denial_reference'] = self._uncertain_append_receipt_digest
            value['reconciliation_required'] = True
        return {'content': [{'type': 'text', 'text': _json_bytes(value).decode('utf-8')}], 'isError': True}

    @staticmethod
    def _digest(value: Any) -> str:
        return 'sha256:' + hashlib.sha256(_json_bytes(value)).hexdigest()

    def _ack_pending_context_replays(self, upstream: UpstreamFacade | None=None) -> None:
        target = self.upstream if upstream is None else upstream
        if target is None or not self._pending_context_replay_acks:
            return
        remaining: list[dict[str, str]] = []
        pending = list(self._pending_context_replay_acks)
        for index, acknowledgement in enumerate(pending):
            if acknowledgement['replay_id'] in self._context_replay_acks_awaiting_public_delivery:
                remaining.append(acknowledgement)
                continue
            try:
                acknowledge = getattr(target, 'acknowledge_context_admission_replay', None)
                if callable(acknowledge):
                    request_ack_safe = bool(getattr(target, 'context_admission_replay_ack_request_safe', getattr(target, 'context_admission_replay_safe', False)))
                else:
                    request_ack_safe = False
                if callable(acknowledge) and request_ack_safe:
                    if acknowledge(acknowledgement) is not True:
                        remaining.append(acknowledgement)
                else:
                    target.notify(CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION, acknowledgement)
            except BrokerError as exc:
                if exc.retryable:
                    remaining.extend(pending[index:])
                    self._pending_context_replay_acks = remaining
                    raise
                try:
                    target.notify(CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION, acknowledgement)
                except BrokerError:
                    remaining.extend(pending[index:])
                    break
        self._pending_context_replay_acks = remaining

    def _context_admission(self, arguments: dict[str, Any], *, defer_replay_ack_until_public_delivery: bool=False) -> dict[str, Any]:
        """Rotate one logical context, reconnecting the transport at most once."""
        first_error: BrokerError | None = None
        request_ever_sent = False
        replay_id = 'sha256:' + secrets.token_hex(32)
        replay_arguments: dict[str, Any] | None = None
        for attempt in range(2):
            replay_after_send = False
            admission_call_started = False
            try:
                if self.upstream is None:
                    self._open_upstream(replay_id)
                    assert self.upstream is not None
                    replay_after_send = bool(getattr(self.upstream, 'context_admission_replay_safe', False))
                    self._ack_pending_context_replays()
                    if not replay_after_send:
                        reserve = getattr(self.upstream, 'reserve_context_admission_replay', None)
                        replay_after_send = bool(callable(reserve) and getattr(self.upstream, 'context_admission_replay_contract_safe', getattr(self.upstream, 'context_admission_replay_safe', False)) and reserve(replay_id))
                else:
                    self._ack_pending_context_replays()
                    reserve = getattr(self.upstream, 'reserve_context_admission_replay', None)
                    replay_after_send = bool(callable(reserve) and getattr(self.upstream, 'context_admission_replay_contract_safe', getattr(self.upstream, 'context_admission_replay_safe', False)) and reserve(replay_id))
                assert self.upstream is not None
                if replay_arguments is not None and (not replay_after_send):
                    raise BrokerError('replacement upstream did not retain replay contract', layer='broker-upstream')
                if replay_after_send:
                    if replay_arguments is None:
                        replay_arguments = {**arguments, CONTEXT_ADMISSION_REPLAY_FIELD: replay_id}
                    call_arguments = replay_arguments
                else:
                    call_arguments = arguments
                admission_call_started = True
                result = self.upstream.call_tool('integrity_context_admission', call_arguments)
                if replay_after_send:
                    acknowledgement = {'replay_id': replay_id, 'request_digest': self._digest(arguments), 'response_digest': self._digest(result)}
                    if acknowledgement not in self._pending_context_replay_acks:
                        self._pending_context_replay_acks.append(acknowledgement)
                    if defer_replay_ack_until_public_delivery:
                        self._context_replay_acks_awaiting_public_delivery.add(replay_id)
                return result
            except BrokerError as exc:
                request_ever_sent = request_ever_sent or (admission_call_started and exc.request_sent)
                self.close()
                if attempt or not exc.retryable or (admission_call_started and exc.request_sent and (not replay_after_send)):
                    terminal_error = exc
                    if exc.request_sent != request_ever_sent:
                        terminal_error = BrokerError(str(exc), layer=exc.layer, request_sent=request_ever_sent, retryable=exc.retryable)
                        if request_ever_sent:
                            terminal_error.add_note('an earlier replay-protected admission attempt sent request bytes')
                        else:
                            terminal_error.add_note('only upstream initialization bytes were sent')
                    if first_error is not None:
                        terminal_error.add_note(f'context admission reconnect followed: {first_error}')
                    raise terminal_error
                first_error = exc
        raise AssertionError('unreachable context admission retry state')

    @staticmethod
    def _read_seal_retry(result: dict[str, Any]) -> bool:
        """Accept only the upstream's explicit pre-admission checkpoint denial."""
        if result.get('isError') is not True:
            return False
        content = result.get('content')
        if not isinstance(content, list) or len(content) != 1:
            return False
        block = content[0]
        if not isinstance(block, dict) or block.get('type') != 'text':
            return False
        try:
            document = json.loads(block['text'])
        except (KeyError, TypeError, ValueError):
            return False
        receipt = document.get('receipt') if isinstance(document, dict) else None
        return isinstance(receipt, dict) and all((type(receipt.get(key)) is type(value) and receipt.get(key) == value for key, value in {'tool': 'integrity_context_admission', 'outcome': 'denied', 'failure_layer': 'read-plane-initialization', 'reason_code': 'seed_catalog_checkpoint_required', 'read_plane_status': 'unavailable', 'automatic_retry_allowed': True, 'canonical_writes': 0, 'retry_disposition': 'exact-envelope-after-supported-read-seal'}.items()))

    def _resolve_current_turn(self, arguments: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        unknown = set(arguments) - {'turn_ref', 'budget', 'limit'}
        turn_ref = arguments.get('turn_ref')
        if unknown or not isinstance(turn_ref, str):
            raise BrokerError('current-turn admission arguments are invalid', layer='broker-envelope')
        if 'budget' in arguments and 'limit' in arguments:
            raise BrokerError('budget and limit are mutually exclusive', layer='broker-envelope')
        try:
            prompt, envelope, claim_id = turn_envelope.resolve(turn_ref)
        except (OSError, turn_envelope.TurnEnvelopeError) as exc:
            raise BrokerError(str(exc), layer='broker-envelope') from exc
        self._own_turn_binding = {'hashes': envelope.get('native_identity_hashes'), 'intent_id': envelope.get('registration_intent_id'), 'prompt_sha256': envelope['prompt_sha256'], 'generation': envelope['generation'], 'admitted': False, 'turn_ref_digest': envelope['turn_ref_digest'], 'project_scope_sha256': envelope.get('project_scope_sha256')}
        binding = {key: envelope[key] for key in ('protocol', 'turn_ref_digest', 'prompt_sha256', 'prompt_bytes', 'segment_count', 'prompt_coverage', 'truncation', 'generation')}
        expanded: dict[str, Any] = {'intent': prompt, '_integrity_turn_binding': binding}
        if 'project_scope' in envelope:
            binding['project_scope'] = envelope['project_scope']
            binding['project_scope_sha256'] = envelope['project_scope_sha256']
        for key in ('budget', 'limit'):
            if key in arguments:
                expanded[key] = arguments[key]
        try:
            native = turn_envelope._native_owning_head(_integrity_value('claude_session_id'))
            expected_thread = hashlib.sha256(_integrity_value('claude_session_id').encode()).hexdigest()
            if self._own_turn_binding['hashes']['thread_id'] != expected_thread or self._own_turn_binding['hashes']['turn_id'] != hashlib.sha256(native['id'].encode()).hexdigest() or native['status'] != 'inProgress':
                raise ValueError('foreign Claude native binding')
        except Exception:
            turn_envelope.release_claim(turn_ref, claim_id)
            self._own_turn_binding = None
            raise BrokerError('claude_own_native_binding_required', layer='broker-envelope') from None
        return (turn_ref, claim_id, expanded)

    def _standalone_turn_memory_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run one idempotent lifecycle call on an isolated, retryable transport."""
        self._check_own_lifecycle(name, arguments)
        if self.upstream is not None and self.bound:
            # Option 4: lifecycle calls go to the admitted warm stream first. The
            # server replays an open/close with the same subject, so a fault after
            # the request was sent is reported, not resent here.
            try:
                self._ack_pending_context_replays()
            except BrokerError as exc:
                # As below: an ACK fault desynchronizes only the admitted stream.
                try:
                    self.close()
                except Exception as cleanup_error:
                    self._last_cleanup_failure_type = type(cleanup_error).__name__
                    exc.add_note(f'secondary cleanup failed: {type(cleanup_error).__name__}')
            else:
                try:
                    if getattr(self, '_post_admission_open_active', False):
                        return self.upstream.request('tools/call', {'name': name, 'arguments': arguments},
                                                     timeout=self.POST_ADMISSION_OPEN_TIMEOUT_SECONDS)
                    return self.upstream.call_tool(name, arguments)
                except BrokerError as exc:
                    if exc.request_sent or getattr(self, '_post_admission_open_active', False):
                        raise
        if getattr(self, '_post_admission_open_active', False):
            raise BrokerError('post-admission open requires the admitted warm stream',
                              layer='broker-post-admission-open', request_sent=False, retryable=False)
        if self.upstream is not None:
            try:
                self._ack_pending_context_replays()
            except BrokerError as exc:
                try:
                    self.close()
                except Exception as cleanup_error:
                    self._last_cleanup_failure_type = type(cleanup_error).__name__
                    exc.add_note(f'secondary cleanup failed: {type(cleanup_error).__name__}')
        first_error: BrokerError | None = None
        for attempt in range(2):
            target: UpstreamFacade | None = None
            primary_error: BrokerError | None = None
            try:
                cleanup_reservation_id = self._pending_context_replay_acks[0]['replay_id'] if self._pending_context_replay_acks else None
                target = self._new_upstream(cleanup_reservation_id)
                self._ack_pending_context_replays(target)
                return target.call_tool(name, arguments)
            except BrokerError as exc:
                primary_error = exc
                if attempt or not exc.retryable:
                    if first_error is not None:
                        exc.add_note(f'turn-memory reconnect followed: {first_error}')
                    raise
                first_error = exc
            finally:
                if target is not None:
                    try:
                        target.close()
                    except Exception as cleanup_error:
                        self._last_cleanup_failure_type = type(cleanup_error).__name__
                        if primary_error is not None:
                            primary_error.add_note(f'secondary cleanup failed: {type(cleanup_error).__name__}')
        raise AssertionError('unreachable Turn Memory retry state')

    POST_ADMISSION_OPEN_TIMEOUT_SECONDS = 4.0
    TURN_REGISTRATION_HANDOFF_PROTOCOL = 'integrity-client/broker-turn-registration-handoff/v1'

    @staticmethod
    def _registration_receipt(result, arguments):
        """Return the signed registration receipt for exactly ``arguments``, else None."""
        try:
            if not isinstance(result, dict) or result.get('isError') is True:
                return None
            value = result.get('structuredContent')
            if value is None:
                content = result['content']
                if len(content) != 1 or content[0].get('type') != 'text':
                    return None
                value = json.loads(content[0]['text'])
            receipt = value['receipt']
            unsigned = {k: v for k, v in receipt.items() if k not in {'signature', 'receipt_id'}}
            raw = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            expected = 'sha256:' + hashlib.sha256(b'turn-memory-registration-v1\x00' + raw).hexdigest()
            identity = {key: arguments[key] for key in ('machine_id', 'thread_id', 'turn_id', 'intent_id')}
            if (receipt.get('protocol') != 'integrity-guardian/turn-memory-registration/v1'
                    or receipt.get('receipt_id') != expected or receipt.get('identity') != identity
                    or receipt.get('prompt_sha256') != arguments['prompt_sha256']
                    or receipt.get('terminal_required') is not True
                    or receipt.get('production_authority') is not False
                    or re.fullmatch('sha256:[a-f0-9]{64}', str(receipt.get('namespace_fingerprint'))) is None
                    or receipt.get('signature', {}).get('algorithm') != 'ed25519'):
                return None
            return receipt
        except (KeyError, TypeError, ValueError, AttributeError, IndexError, RecursionError):
            return None

    def _open_own_registration_after_admission(self):
        """Option 4: open this turn's registration over the admitted warm stream.

        Runs before the admission response is delivered, so the owning hook finds
        the receipt instead of starting a cold client. The identity is the profile's
        own Claude session, its current Native turn and the owning state, never
        model input, and the hook must have asked for the hand-off for this intent.
        The send goes through _standalone_turn_memory_call (ownership checks, warm
        stream first) with a short timeout. The admission result is never changed.
        Without a hand-off the hook opens the registration itself; the server
        replays an open with the same identity and prompt.
        """
        name = 'integrity_turn_memory_open'
        self._post_admission_open_stage = 'not-attempted'
        binding = self._own_turn_binding
        try:
            if (not self.bound or self.upstream is None or not isinstance(binding, dict)
                    or binding.get('admitted') is not True):
                self._post_admission_open_stage = 'skipped-no-owning-binding'
                return
            thread = _integrity_value('claude_session_id')
            head = turn_envelope._native_owning_head(thread)
            hashes = binding['hashes']
            root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home() / '.codex/integrity-memory/state')))
            path = root / (hashes['thread_id'] + '.json')
            if path.is_symlink() or not path.is_file():
                raise ValueError('state unavailable')
            state = json.loads(path.read_bytes())
            arguments = {'machine_id': turn_envelope._machine_id(), 'thread_id': thread, 'turn_id': head.get('id'),
                         'intent_id': binding['intent_id'], 'prompt_sha256': binding['prompt_sha256']}
            sha = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest()  # noqa: E731
            consent = state.get('turn_memory_registration_handoff')
            if (head.get('status') != 'inProgress' or state.get('turn_id') != arguments['turn_id']
                    # Only a hook that takes the hand-off for this intent asked for it.
                    or consent != {'protocol': self.TURN_REGISTRATION_HANDOFF_PROTOCOL, 'intent_id': binding['intent_id']}
                    or state.get('turn_memory_status') != 'provisional'
                    or state.get('turn_memory_generation') != binding['generation']
                    or state.get('turn_memory_intent_id') != binding['intent_id']
                    or state.get('prompt_sha256') != binding['prompt_sha256']
                    or 'turn_memory_registration_id' in state or 'model_mcp_context_admission_id' in state
                    or any(not isinstance(arguments[key], str) or sha(arguments[key]) != hashes.get(key)
                           for key in ('machine_id', 'thread_id', 'turn_id'))):
                self._post_admission_open_stage = 'skipped-state-not-provisional'
                return
        except (BrokerError, OSError, ValueError, KeyError, TypeError, AttributeError, turn_envelope.TurnEnvelopeError):
            self._post_admission_open_stage = 'skipped-precheck-failed'
            return
        self._post_admission_open_active = True
        try:
            result = self._standalone_turn_memory_call(name, arguments)
        except BrokerError as error:
            self._post_admission_open_stage = 'send-outcome-unknown' if error.request_sent else 'skipped-' + error.layer
            return
        finally:
            self._post_admission_open_active = False
        receipt = self._registration_receipt(result, arguments)
        if receipt is None:
            self._post_admission_open_stage = 'receipt-invalid'
            return
        record = {'protocol': self.TURN_REGISTRATION_HANDOFF_PROTOCOL, 'turn_ref_digest': binding['turn_ref_digest'],
                  'generation': binding['generation'], 'intent_id': binding['intent_id'],
                  'arguments': arguments, 'receipt': receipt}
        try:
            turn_envelope._write_atomic(root / ('turn-registration-handoff-' + hashes['thread_id'] + '.json'), record)
        except (OSError, ValueError, turn_envelope.TurnEnvelopeError):
            self._post_admission_open_stage = 'handoff-write-failed'
            return
        self._post_admission_open_stage = 'handed-off'

    def _adopt_admitted_own_binding(self, result):
        binding = self._own_turn_binding
        if not isinstance(binding, dict):
            return
        binding['admitted'] = False
        try:
            content = result['content']
            if result.get('isError') is True or len(content) != 1 or content[0]['type'] != 'text':
                return
            value = json.loads(content[0]['text'])
            prompt = value['prompt_binding']
            valid = value['protocol'] in {'integrity-client-memory-mcp/v3/context-admission/v1', 'integrity-client-memory-mcp/v3/context-admission/v2'} and re.fullmatch('sha256:[a-f0-9]{64}', value['context_admission_id']) is not None and (value['snapshot']['immutable'] is True) and (value['snapshot']['source_namespace'] == _integrity_value('seed_namespace')) and (value['home_record_count'] == 0) and (value['production_authority'] is False) and (prompt['prompt_sha256'] == binding['prompt_sha256']) and (prompt['generation'] == binding['generation']) and (prompt['turn_ref_digest'] == binding['turn_ref_digest']) and (prompt['truncation'] is False) and (binding['project_scope_sha256'] is None or prompt.get('project_scope_sha256') == binding['project_scope_sha256'])
            if valid:
                binding['admitted'] = True
                binding['context_admission_id'] = value['context_admission_id']
        except (KeyError, TypeError, ValueError, RecursionError):
            return

    @staticmethod
    def _own_registration_content(state, binding):
        try:
            receipt = state['turn_memory_registration_receipt']
            unsigned = {k: v for k, v in receipt.items() if k not in {'signature', 'receipt_id'}}
            raw = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            expected = 'sha256:' + hashlib.sha256(b'turn-memory-registration-v1\x00' + raw).hexdigest()
            identity = receipt['identity']
            hashes = binding['hashes']
            return set(identity) == {'machine_id', 'thread_id', 'turn_id', 'intent_id'} and receipt['protocol'] == 'integrity-guardian/turn-memory-registration/v1' and (receipt['receipt_id'] == expected == state['turn_memory_registration_id']) and (receipt['namespace_fingerprint'] == state['turn_memory_namespace_fingerprint'] == _integrity_value('pin_dd9fa64be3f2')) and (receipt['prompt_sha256'] == binding['prompt_sha256']) and (identity['intent_id'] == binding['intent_id']) and all((hashlib.sha256(identity[key].encode()).hexdigest() == hashes[key] for key in ('machine_id', 'thread_id', 'turn_id'))) and (receipt['signature']['algorithm'] == 'ed25519') and (receipt['terminal_required'] is True) and (receipt['production_authority'] is False)
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def _check_own_lifecycle(self, name, arguments):
        if name == 'integrity_turn_memory_coverage':
            return
        if self._owning_hook_lifecycle_ref is not None:
            ref = self._owning_hook_lifecycle_ref
            self._owning_hook_lifecycle_ref = None
            try:
                turn_envelope.consume_owning_lifecycle(ref, name, arguments)
            except (OSError, ValueError, turn_envelope.TurnEnvelopeError):
                raise BrokerError('owning_hook_lifecycle_handoff_invalid', layer='broker-owning-lifecycle') from None
            return
        binding = self._own_turn_binding
        if not self.bound or not isinstance(binding, dict) or binding.get('admitted') is not True:
            raise BrokerError('owning_admitted_binding_required', layer='broker-owning-lifecycle')
        if not isinstance(binding, dict) or not isinstance(binding.get('hashes'), dict):
            raise BrokerError('owning_turn_binding_required', layer='broker-owning-lifecycle')
        hashes = binding['hashes']
        sha = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest()
        if name == 'integrity_turn_memory_open':
            expected = {'machine_id', 'thread_id', 'turn_id', 'intent_id', 'prompt_sha256'}
            if set(arguments) != expected or arguments.get('intent_id') != binding['intent_id'] or re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', arguments.get('turn_id', '')) is None or (arguments.get('prompt_sha256') != binding['prompt_sha256']) or any((not isinstance(arguments.get(key), str) or sha(arguments[key]) != hashes.get(key) for key in ('machine_id', 'thread_id', 'turn_id'))):
                raise BrokerError('foreign_registration_open_denied', layer='broker-owning-lifecycle')
            return
        if name not in {'integrity_turn_memory_close', 'integrity_turn_memory_gap'}:
            raise BrokerError('owning_lifecycle_tool_invalid', layer='broker-owning-lifecycle')
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home() / '.codex/integrity-memory/state')))
        path = root / (hashes['thread_id'] + '.json')
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError('state unavailable')
            state = json.loads(path.read_bytes())
            valid = state.get('turn_memory_registration_id') == arguments.get('registration_id') and ('model_mcp_context_admission_id' not in state or state['model_mcp_context_admission_id'] == binding.get('context_admission_id')) and self._own_registration_content(state, binding) and (state.get('prompt_sha256') == binding['prompt_sha256']) and (state.get('turn_memory_generation') == binding['generation']) and (state.get('turn_memory_intent_id') == binding['intent_id']) and isinstance(state.get('turn_id'), str) and (sha(state['turn_id']) == hashes['turn_id'])
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise BrokerError('foreign_or_historical_close_requires_owning_recovery', layer='broker-owning-lifecycle')

    def dispatch(self, message: dict[str, Any], *, defer_replay_ack_until_public_delivery: bool=False) -> dict[str, Any] | None:
        request_id = message.get('id')
        method = message.get('method')
        if message.get('jsonrpc') != '2.0' or not isinstance(method, str):
            return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32600, 'message': 'invalid request'}}
        if method.startswith('notifications/') or 'id' not in message:
            return None
        params = message.get('params', {})
        if not isinstance(params, dict):
            return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32602, 'message': 'params must be an object'}}
        if method == 'initialize':
            self.initialize_params = dict(params)
            requested = params.get('protocolVersion')
            protocol = requested if isinstance(requested, str) else DEFAULT_MCP_VERSION
            result = {'protocolVersion': protocol, 'capabilities': {'tools': {'listChanged': False}}, 'serverInfo': {'name': BROKER_NAME, 'version': BROKER_VERSION}, 'instructions': SERVER_INSTRUCTIONS if CURRENT_TURN_CONTEXT_TOOL in self.tool_names else LEGACY_SERVER_INSTRUCTIONS}
        elif method == 'ping':
            result = {}
        elif method == 'tools/list':
            result = {'tools': self.tools_contract}
        elif method == 'tools/call':
            name = params.get('name')
            arguments = params.get('arguments', {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32602, 'message': 'invalid tool call'}}
            if name not in self.tool_names:
                return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32602, 'message': 'unknown tool'}}
            try:
                if name in STANDALONE_TURN_MEMORY_TOOLS:
                    result = self._standalone_turn_memory_call(name, arguments)
                    return {'jsonrpc': '2.0', 'id': request_id, 'result': result}
                if name in {'integrity_context_admission', CURRENT_TURN_CONTEXT_TOOL}:
                    self.bound = False
                    self._own_turn_binding = None
                    turn_ref: str | None = None
                    claim_id: str | None = None
                    admission_arguments = arguments
                    if name == CURRENT_TURN_CONTEXT_TOOL:
                        turn_ref, claim_id, admission_arguments = self._resolve_current_turn(arguments)
                    elif set(arguments) - {'intent', 'budget', 'limit'}:
                        raise BrokerError('legacy admission accepts only public intent/budget/limit fields', layer='broker-envelope')
                    result = self._context_admission(admission_arguments, defer_replay_ack_until_public_delivery=defer_replay_ack_until_public_delivery)
                    self.bound = result.get('isError') is not True
                    if self.bound:
                        self._binding_loss_receipt_digest = None
                        self._adopt_admitted_own_binding(result)
                        if name == CURRENT_TURN_CONTEXT_TOOL:
                            self._open_own_registration_after_admission()
                    if turn_ref is not None and claim_id is not None:
                        if self._read_seal_retry(result):
                            try:
                                turn_envelope.release_claim(turn_ref, claim_id)
                            except (OSError, turn_envelope.TurnEnvelopeError) as error:
                                raise BrokerError('read-seal retry claim could not be released', layer='broker-envelope', request_sent=True, retryable=False) from error
                            turn_ref = claim_id = None
                        elif defer_replay_ack_until_public_delivery:
                            pending = (turn_ref, claim_id)
                            if pending not in self._turn_envelopes_awaiting_public_delivery:
                                self._turn_envelopes_awaiting_public_delivery.append(pending)
                        else:
                            delivered_ref, delivered_claim = (turn_ref, claim_id)
                            turn_ref = claim_id = None
                            self._consume_delivered_turn_envelope(delivered_ref, delivered_claim)
                    # 7.0.1 response diet: the model gets a file-backed compact admission
                    # (at most 8 KB); the owning hook resolves the full document and runs
                    # its usual validation on it.
                    presenter = getattr(self, '_compact_presenter', None)
                    if presenter is None:
                        presenter = self._compact_presenter = _compact_admission.Presenter()
                    context_key = ((getattr(self, '_own_turn_binding', None) or {}).get('hashes') or {}).get('thread_id')
                    return {'jsonrpc': '2.0', 'id': request_id, 'result': presenter.present(result, context_key=context_key)}
                elif name == 'integrity_append_event' and self._uncertain_append_receipt_digest:
                    raise BrokerError('append outcome unresolved; reconcile through owning writer before further writes', layer='broker-append-uncertain', request_sent=False, retryable=False)
                elif self.upstream is None or not self.bound:
                    if self.upstream is not None:
                        try:
                            self._ack_pending_context_replays()
                        except BrokerError as exc:
                            raise BrokerError(str(exc), layer=exc.layer, request_sent=False, retryable=exc.retryable) from exc
                    raise BrokerError('upstream logical context was lost; delivered admission has no supported reattach' if self._binding_loss_receipt_digest else 'current intent has no admitted upstream facade', layer='broker-context-lost' if self._binding_loss_receipt_digest else 'broker-binding-missing')
                assert self.upstream is not None
                try:
                    self._ack_pending_context_replays()
                except BrokerError as exc:
                    raise BrokerError(str(exc), layer=exc.layer, request_sent=False, retryable=exc.retryable) from exc
                result = self.upstream.call_tool(name, arguments)
                self._observe_upstream_denial(name, result)
                if name == 'integrity_append_event':
                    result = _compact_append_result(result)
            except BrokerError as exc:
                if name == 'integrity_append_event' and exc.request_sent:
                    self._uncertain_append_receipt_digest = self._digest({'tool': name, 'arguments_digest': self._digest(arguments), 'outcome': 'unknown', 'failure_layer': exc.layer})
                if name == CURRENT_TURN_CONTEXT_TOOL and turn_ref is not None and (claim_id is not None):
                    if not exc.request_sent and exc.layer == 'broker-upstream':
                        try:
                            turn_envelope.release_claim(turn_ref, claim_id)
                            turn_ref = claim_id = None
                        except (OSError, turn_envelope.TurnEnvelopeError) as release_error:
                            exc = BrokerError('pre-send turn envelope claim could not be released', layer='broker-envelope', request_sent=False, retryable=False)
                            exc.add_note(str(release_error))
                    elif defer_replay_ack_until_public_delivery:
                        pending = (turn_ref, claim_id)
                        if pending not in self._turn_envelopes_awaiting_public_delivery:
                            self._turn_envelopes_awaiting_public_delivery.append(pending)
                        turn_ref = claim_id = None
                    else:
                        delivered_ref, delivered_claim = (turn_ref, claim_id)
                        turn_ref = claim_id = None
                        try:
                            self._consume_delivered_turn_envelope(delivered_ref, delivered_claim)
                        except BrokerError as consume_error:
                            exc = consume_error
                if name not in STANDALONE_TURN_MEMORY_TOOLS and name not in {'integrity_context_admission', CURRENT_TURN_CONTEXT_TOOL} and (exc.retryable or not self._pending_context_replay_acks) and (exc.layer not in {'broker-append-uncertain', 'broker-context-lost'}):
                    try:
                        self.close()
                    except Exception as cleanup_error:
                        exc.add_note(f'secondary broker cleanup failed: {type(cleanup_error).__name__}')
                result = self._denial(name, exc)
        else:
            return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32601, 'message': 'method not found'}}
        return {'jsonrpc': '2.0', 'id': request_id, 'result': result}

    def _consume_delivered_turn_envelope(self, turn_ref: str, claim_id: str) -> None:
        try:
            turn_envelope.commit(turn_ref, claim_id)
            return
        except (OSError, turn_envelope.TurnEnvelopeError) as commit_error:
            try:
                turn_envelope.retire(turn_ref)
            except (OSError, turn_envelope.TurnEnvelopeError) as retire_error:
                self.close()
                raise BrokerError('delivered turn envelope could not be consumed', layer='broker-envelope', request_sent=True, retryable=False) from retire_error
            self.close()
            raise BrokerError('delivered turn envelope tombstone failed; payload retired', layer='broker-envelope', request_sent=True, retryable=False) from commit_error

    def confirm_public_response_delivery(self) -> None:
        """Make only responses flushed to the public client eligible for ACK."""
        self._context_replay_acks_awaiting_public_delivery.clear()
        pending = self._turn_envelopes_awaiting_public_delivery
        self._turn_envelopes_awaiting_public_delivery = []
        for turn_ref, claim_id in pending:
            self._consume_delivered_turn_envelope(turn_ref, claim_id)

    def shutdown(self) -> None:
        """Retire delivered replay state only on graceful public EOF."""
        try:
            if self.upstream is None and self._pending_context_replay_acks:
                self._open_upstream(self._pending_context_replay_acks[0]['replay_id'])
            self._ack_pending_context_replays()
        except BrokerError:
            pass
        finally:
            self.close()

def serve(broker: TurnBroker) -> int:
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
            if not raw:
                break
            try:
                if len(raw) > MAX_MESSAGE_BYTES:
                    raise ValueError('request exceeds limit')
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise TypeError('request must be an object')
                response = broker.dispatch(message, defer_replay_ack_until_public_delivery=True)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                response = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'parse error'}}
            if response is not None:
                payload = _json_bytes(response) + b'\n'
                written_total = 0
                while written_total < len(payload):
                    written = sys.stdout.buffer.write(memoryview(payload)[written_total:])
                    if not isinstance(written, int) or isinstance(written, bool) or written <= 0 or (written > len(payload) - written_total):
                        raise BrokenPipeError('public response transport made no progress')
                    written_total += written
                sys.stdout.buffer.flush()
                try:
                    broker.confirm_public_response_delivery()
                except BrokerError:
                    broker.close()
                    print('Integrity broker: post-delivery custody failure; binding closed', file=sys.stderr, flush=True)
        return 0
    finally:
        broker.shutdown()

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--upstream-server', required=True)
    parser.add_argument('--tools-contract', type=Path, required=True)
    args = parser.parse_args(argv)
    tools_contract = _load_tools_contract(args.tools_contract)
    return serve(TurnBroker(args.config, args.upstream_server, tools_contract))
if __name__ == "__main__":
    _integrity_require_config()

if __name__ == '__main__':
    raise SystemExit(main())
