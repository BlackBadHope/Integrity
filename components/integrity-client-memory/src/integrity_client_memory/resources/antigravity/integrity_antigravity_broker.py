#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Managed Antigravity broker, isolated by conversationId; no ambient subject."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import antigravity_state as store
import turn_broker_core as core
HERE=Path(__file__).resolve().parent
MAX_CONVERSATION_WORKERS=4

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


ADMISSION_COMPACT_PROTOCOL = "integrity-admission-projection/v1"
ADMISSION_COMPACT_LIMIT = 8192


def _pick(value, *path):
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def compact_admission_document(value):
    """Model-facing admission: the ids, the capsule and the health, not the static blocks.

    The broker validated the full admission before this runs. Static blocks
    (capabilities, facade, lifecycle, operations, the repeated authority
    contracts) are replaced by their digest; the capsule text is clipped only if
    the projection would exceed 8 KB.
    """
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    mind = _pick(value, "mind", "mind") or {}
    projection = {
        "protocol": value.get("protocol"),
        "context_admission_id": value.get("context_admission_id"),
        "health": value.get("health"),
        "status": value.get("status"),
        "logical_generation": value.get("logical_generation"),
        "production_authority": value.get("production_authority"),
        "home_record_count": value.get("home_record_count"),
        "snapshot": {"snapshot_id": _pick(value, "snapshot", "snapshot_id"),
                     "cursor": _pick(value, "snapshot", "cursor")},
        "context_delivery": {key: _pick(value, "context_delivery", key)
                             for key in ("health", "status", "read_plane", "notify_owner_required")},
        "write_plane": value.get("write_plane"),
        "prompt_binding": {key: _pick(value, "prompt_binding", key)
                           for key in ("turn_ref_digest", "prompt_sha256", "generation")},
        "receipts": {"mind_admission": _pick(value, "mind", "admission_receipt", "receipt_id"),
                     "architecture_admission": _pick(value, "architecture", "architecture", "admission_id"),
                     "selection": _pick(value, "mind", "selection_receipt", "receipt_id")},
        "capabilities_digest": _pick(value, "capabilities", "capabilities_digest"),
        "capsule": {"door": _pick(mind, "synaptic", "door"),
                    "moves": _pick(mind, "synaptic", "moves"),
                    "learned_hints": _pick(mind, "synaptic", "learned_hints"),
                    "context_text": _pick(mind, "working_set", "context_text"),
                    # Recalled memory is the part a model acts on; keep it, shortened.
                    "recall_hits": [{key: (hit.get(key)[:400] if key == "summary" and isinstance(hit.get(key), str)
                                           else hit.get(key))
                                     for key in ("id", "kind", "task_id", "truth_status", "summary")}
                                    for hit in (_pick(mind, "working_set", "recall_hits") or [])
                                    if isinstance(hit, dict)],
                    "invariants": _pick(mind, "working_set", "invariants"),
                    "attention_items": _pick(mind, "working_set", "attention_items"),
                    "plan_items": _pick(mind, "working_set", "plan_items")},
        "compaction": {"protocol": ADMISSION_COMPACT_PROTOCOL,
                       "full_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                       "full_bytes": len(raw.encode("utf-8")),
                       "omitted": "static capabilities, facade, lifecycle, operations, processing and "
                                  "repeated authority contracts; unchanged since capabilities_digest"},
    }
    def size():
        return len(json.dumps(projection, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    hits = projection["capsule"]["recall_hits"]
    while size() > ADMISSION_COMPACT_LIMIT and hits:
        hits.pop()
    for key in ("plan_items", "attention_items"):
        if size() > ADMISSION_COMPACT_LIMIT:
            projection["capsule"][key] = None
    text = projection["capsule"]["context_text"]
    while size() > ADMISSION_COMPACT_LIMIT and isinstance(text, str) and text:
        text = text[: max(0, len(text) - max(256, (size() - ADMISSION_COMPACT_LIMIT) + 64))]
        projection["capsule"]["context_text"] = text + " [clipped]"
    if size() > ADMISSION_COMPACT_LIMIT:
        projection["capsule"] = {"door": projection["capsule"]["door"], "context_text": None}
    return projection


def compact_admission_result(result):
    """Replace the validated admission block and the registration block for the model."""
    try:
        content = result.get("content")
        if not isinstance(content, list) or not content or content[0].get("type") != "text":
            return result
        out = []
        for index, block in enumerate(content):
            if block.get("type") != "text":
                out.append(block)
                continue
            try:
                value = json.loads(block["text"])
            except ValueError:
                out.append(block)
                continue
            if index == 0 and isinstance(value, dict) and "context_admission_id" in value:
                value = compact_admission_document(value)
            elif isinstance(value, dict) and isinstance(value.get("antigravity_turn_memory"), dict):
                info = value["antigravity_turn_memory"]
                value = {"antigravity_turn_memory": {key: info[key] for key in
                                                     ("registration_id", "close_required", "llm_bus_pointers")
                                                     if key in info}}
            else:
                out.append(block)
                continue
            out.append({"type": "text", "text": json.dumps(value, ensure_ascii=False, separators=(",", ":"))})
        compacted = {key: item for key, item in result.items() if key != "structuredContent"}
        compacted["content"] = out
        return compacted
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return result


def snapshot_bound_tools(contract):
    # Seed read tools whose input schema carries snapshot_id.
    return {t['name'] for t in contract if isinstance(t,dict) and 'snapshot_id' in ((t.get('inputSchema') or {}).get('properties') or {})}

def bind_snapshot(name,arguments,state,tools):
    # Models omit snapshot_id; the server then refuses "snapshot_id does not match session admission".
    # Fill only a missing value from this turn's verified admission; never override a supplied one.
    if name in tools and not arguments.get('snapshot_id') and state.get('admission_verified') and store.DIGEST.fullmatch(str(state.get('snapshot_id') or '')):
        arguments['snapshot_id']=state['snapshot_id']
    return arguments

class ConversationBroker:
    def __init__(self,config,contract,*,root=store.ROOT,factory=None):
        self.root=Path(root);self.config=Path(config);self.contract=contract
        self.control=core.TurnBroker(self.config,'integrity-upstream',contract)
        self.factory=factory or (lambda:core.TurnBroker(self.config,'integrity-upstream',contract))
        self.contexts={};self.pending=[]
        self.snapshot_tools=snapshot_bound_tools(contract)

    def worker(self,conversation,state):
        # At most MAX_CONVERSATION_WORKERS upstream workers; the least recently used one is shut
        # down (unless it still owes a public delivery) before a new conversation gets its own.
        if conversation in self.contexts:
            worker=self.contexts.pop(conversation)
        else:
            while len(self.contexts)>=MAX_CONVERSATION_WORKERS:
                evicted=self.contexts.pop(next(iter(self.contexts)))
                if evicted not in self.pending:evicted.shutdown()
            worker=self.factory();worker.initialize_params=self.control.initialize_params.copy()
            worker.envelopes=store.EnvelopeStore(self.root/'turn-envelopes'/conversation)
        self.contexts[conversation]=worker;worker.model_name=state['model_name']
        return worker

    def dispatch(self,message,*,defer_replay_ack_until_public_delivery=False):
        if message.get('method')!='tools/call':
            response=self.control.dispatch(message)
            if message.get('method')=='tools/list' and response and 'result' in response:
                response=copy.deepcopy(response)
                for tool in response['result'].get('tools',[]):
                    # Antigravity's function schema has no 'not'; the server still validates it.
                    schema=tool.setdefault('inputSchema',{})
                    schema.pop('not',None)
                    schema.setdefault('properties',{})[store.ROUTE_FIELD]={'type':'string','description':'Reserved local hook route; supplied by PreToolUse, never by the model.'}
            return response
        request=copy.deepcopy(message);params=request.get('params',{});name=params.get('name');arguments=params.get('arguments',{})
        try:
            route=arguments.pop(store.ROUTE_FIELD,None);binding=store.consume_route(self.root,route,name,arguments);conversation=binding['conversation_id']
            with store.locked(self.root,conversation):
                state=store.load(self.root,conversation)
                if not state or state['generation']!=binding['generation'] or state['model_name']!=binding['model_name'] or state.get('stopped'):raise ValueError('hook-route-generation-stale')
                worker=self.worker(conversation,state)
                if name=='integrity_context_admission_current_turn':
                    state['admission_verified']=False
                    store.save(self.root,conversation,state)
                if name=='integrity_context_admission':raise ValueError('free-admission-disabled')
                if name=='integrity_append_event' and (not state.get('admission_verified') or not state.get('registration_id') or state.get('turn_memory_closed') or arguments.get('context_admission_id')!=state.get('admission_id')):raise ValueError('current-admission-and-live-registration-required')
                if name=='integrity_turn_memory_open':raise ValueError('registration-open-is-broker-owned')
                if name in {'integrity_turn_memory_close','integrity_turn_memory_gap'} and arguments.get('registration_id')!=state.get('registration_id'):raise ValueError('foreign-registration-refused')
                bind_snapshot(name,arguments,state,self.snapshot_tools)
                response=worker.dispatch(request,defer_replay_ack_until_public_delivery=defer_replay_ack_until_public_delivery)
                if defer_replay_ack_until_public_delivery and worker not in self.pending:self.pending.append(worker)
                if response is None:return None
                result=response.get('result',{})
                if name=='integrity_context_admission_current_turn':
                    state['admission_verified']=False;value=store.unwrap(result);admission=value.get('admission',value)
                    snapshot=admission.get('snapshot');snapshot_id=admission.get('snapshot_id') or (snapshot.get('snapshot_id') if isinstance(snapshot,dict) else None)
                    if not store.DIGEST.fullmatch(str(admission.get('context_admission_id',''))) or not store.DIGEST.fullmatch(str(snapshot_id or '')):raise ValueError('admission-receipt-invalid')
                    state.update(admission_verified=True,admission_id=admission['context_admission_id'],snapshot_id=snapshot_id)
                    opened_args={k:state[k] for k in ('machine_id','turn_id','prompt_sha256')};opened_args['thread_id']=conversation
                    superseded=state.pop('superseded_registration_id',None)
                    state['registration_open_attempted']=True;store.save(self.root,conversation,state)
                    if superseded:
                        # Best effort: the previous owner turn's open registration becomes signed debt.
                        try:worker._standalone_turn_memory_call('integrity_turn_memory_gap',{'registration_id':superseded,'stage':'notify'})
                        except Exception:pass
                    try:
                        opened=store.unwrap(worker._standalone_turn_memory_call('integrity_turn_memory_open',opened_args));receipt=opened.get('receipt',{})
                        identity={k:opened_args[k] for k in ('machine_id','thread_id','turn_id')}
                        if not store.signed(receipt,'integrity-guardian/turn-memory-registration/v1') or receipt.get('identity')!=identity or receipt.get('prompt_sha256')!=state['prompt_sha256'] or receipt.get('production_authority') is not False or receipt.get('terminal_required') is not True:raise ValueError('registration-receipt-invalid')
                        state['registration_id']=receipt['receipt_id'];state['registration_receipt']=receipt
                        tm_info={'registration_id':receipt['receipt_id'],'receipt':receipt,'close_required':True}
                        if state.get('bus_pointers'):tm_info['llm_bus_pointers']=state['bus_pointers']
                        result.setdefault('content',[]).append({'type':'text','text':json.dumps({'antigravity_turn_memory':tm_info},ensure_ascii=False)})
                    except Exception:
                        state['coverage_status']='registration-unresolved'
                        result.setdefault('content',[]).append({'type':'text','text':'TURN MEMORY registration unavailable; canonical reads remain available; append gated. Do not repeat open on unknown outcome.'})
                elif not result.get('isError'):
                    if name=='integrity_turn_memory_close':
                        receipt=store.unwrap(result).get('receipt',{})
                        if not store.signed(receipt,'integrity-guardian/turn-memory-terminal-receipt/v1') or receipt.get('registration_id')!=state.get('registration_id'):raise ValueError('terminal-receipt-invalid')
                        state.update(turn_memory_closed=True,terminal_receipt_id=receipt['receipt_id'],coverage_status='closed')
                    if state.get('bus_pointers'):
                        result.setdefault('content',[]).append({'type':'text','text':json.dumps({'antigravity_bus_pointers':state['bus_pointers']},ensure_ascii=False)})
                store.save(self.root,conversation,state)
                # 7.0.1 response diet: the model-facing edge only; everything above validated the full result.
                if name=='integrity_context_admission_current_turn' and not result.get('isError'):
                    response={**response,'result':compact_admission_result(result)}
                elif name=='integrity_append_event':
                    response={**response,'result':_compact_append_result(result)}
                return response
        except (OSError,ValueError,KeyError,TypeError) as error:
            code=str(error) if isinstance(error,ValueError) and re.fullmatch(r'[a-z0-9-]{3,80}',str(error)) else type(error).__name__
            return {'jsonrpc':'2.0','id':message.get('id'),'result':{'isError':True,'content':[{'type':'text','text':'integrity: broker rejected request: '+code+'. Report this code to the owner; do not debug the broker or hooks yourself.'}]}}

    def confirm_public_response_delivery(self):
        pending,self.pending=self.pending,[]
        for worker in pending:worker.confirm_public_response_delivery()
    def close(self):
        for worker in self.pending:worker.close()
        self.pending=[]
    def shutdown(self):
        self.control.shutdown()
        for worker in self.contexts.values():worker.shutdown()

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--tools-contract',type=Path,required=True);a=p.parse_args()
    return core.serve(ConversationBroker(a.config,core._load_tools_contract(a.tools_contract)))
if __name__ == "__main__":
    _integrity_require_config()

if __name__=='__main__':raise SystemExit(main())
