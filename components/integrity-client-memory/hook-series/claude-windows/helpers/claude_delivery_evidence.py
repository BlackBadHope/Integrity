"""Read-only Claude delivery join. It grants no admission or target authority.

The sender argument is supplied only by the pinned, authenticated Medor Native
observer. It must never be populated from a hook payload or a model JSON proof.
Local identities remain CLI delivery turn, transcript item, and own hook turn.
"""
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sqlite3

UUID=re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
MAX_TRANSCRIPT=8*1024*1024

class ClaudeEvidenceError(ValueError):pass

def need(value,code):
    if not value:raise ClaudeEvidenceError(code)

def sha(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()

def strict_json(raw):
    def unique(pairs):
        out={}
        for key,value in pairs:
            need(key not in out,'claude_evidence_duplicate_json_key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ClaudeEvidenceError('claude_evidence_nonfinite_json')))

def plain(path):
    path=Path(path)
    need(path.is_absolute() and path.is_file() and not path.is_symlink()
         and path.resolve(strict=True)==path,'claude_evidence_path_invalid')
    for ancestor in path.parents:
        need(not ancestor.is_symlink() and ancestor.resolve(strict=True)==ancestor,
             'claude_evidence_path_invalid')
    return path

def readonly(path):
    return sqlite3.connect(plain(path).as_uri()+'?mode=ro',uri=True,timeout=3)

def transcript_current(path,session,body):
    path=plain(path);need(0<path.stat().st_size<=MAX_TRANSCRIPT,'claude_transcript_incomplete')
    raw=path.read_bytes()
    need(0<len(raw)<=MAX_TRANSCRIPT and raw.endswith(b'\n'),'claude_transcript_incomplete')
    current=None
    for line in raw.splitlines():
        item=strict_json(line)
        need(isinstance(item,dict),'claude_transcript_incomplete')
        if item.get('type')!='user':continue
        need(item.get('sessionId')==session and item.get('isSidechain') is False,
             'claude_transcript_subject_mismatch')
        message=item.get('message')
        need(isinstance(message,dict) and message.get('role')=='user','claude_transcript_user_invalid')
        content=message.get('content')
        if isinstance(content,list) and content and all(isinstance(block,dict) and
                block.get('type')=='tool_result' for block in content):continue
        need(isinstance(content,str) and content and not item.get('truncated')
             and not item.get('contentTruncated'),'claude_transcript_user_incomplete')
        current=item
    need(current is not None and current['message']['content']==body,
         'claude_transcript_current_input_mismatch')
    need(UUID.fullmatch(current.get('uuid','')) is not None,'claude_transcript_item_invalid')
    return current

def inspect_current_delivery(payload,hook_state,source,core,profile,*,now,binding_mode='pending',owning_claim=None):
    """Normalize actual local records; caller must still verify owner and controls.

    Core reserve/claim, Scope capture, fresh envelope staging and permission
    policy remain outside this function. This function performs no writes.
    """
    thread=profile['target_thread_id'];host=profile['target_machine_id']
    need(UUID.fullmatch(thread) is not None and payload.get('session_id')==thread
         and payload.get('hook_event_name')=='PreToolUse'
         and payload.get('cwd')==profile['workspace'],'claude_hook_subject_mismatch')
    need(not set(payload)&{'source_evidence','owner_receipt','receiving_evidence','claim_token'},
         'claude_model_proof_forbidden')
    transcript=Path(profile['transcript_root'])/(thread+'.jsonl')
    need(payload.get('transcript_path')==str(transcript),'claude_hook_transcript_mismatch')
    need(isinstance(source,dict) and source.get('thread_id')==core.MEDOR_THREAD
         and source.get('status')=='completed' and source.get('server')=='codex_apps'
         and source.get('tool') in profile['native_claude_send_tools'],'claude_source_send_not_observed')
    arguments=source.get('arguments')
    need(isinstance(arguments,dict) and set(arguments)=={'host_id','thread_id','prompt','request_id'}
         and arguments['host_id']==host and arguments['thread_id']==thread,
         'claude_source_target_mismatch')
    body=arguments['prompt'];operation=arguments['request_id']
    need(isinstance(body,str) and 0<len(body)<=8000 and isinstance(operation,str)
         and 8<=len(operation)<=128,'claude_send_arguments_invalid')
    request=core.parse_request(core.extract_request_body(body),now=now,
        receiving_host_id=host,receiving_thread_id=thread,
        allowed_owner_threads=profile['allowed_owner_threads'])
    need(operation==request['operation_id'],'claude_operation_identity_mismatch')
    forwarded={'thread_id':thread,'prompt':body}
    expected_digest=sha(json.dumps(['claude_send_prompt',forwarded],sort_keys=True,ensure_ascii=False))
    with closing(readonly(profile['operation_ledger'])) as db:
        row=db.execute('SELECT o.digest,o.result,r.error FROM operations o LEFT JOIN operation_rejections r ON r.id=o.id WHERE o.id=?',(operation,)).fetchone()
    need(row is not None and row[0]==expected_digest and row[1] is not None and row[2] is None,
         'claude_delivery_ack_missing_or_conflicting')
    result=strict_json(row[1]);ack=result.get('structuredContent') if isinstance(result,dict) else None
    need(isinstance(ack,dict) and ack.get('thread_id')==thread and ack.get('status')=='starting'
         and ack.get('execution_complete') is False and UUID.fullmatch(ack.get('turn_id','')) is not None,
         'claude_delivery_ack_invalid')
    with closing(readonly(profile['cli_ledger'])) as db:
        task=db.execute('SELECT session_id FROM tasks WHERE id=?',(thread,)).fetchone()
        turn=db.execute('SELECT id,prompt,status,created FROM turns WHERE task_id=? ORDER BY created DESC LIMIT 1',(thread,)).fetchone()
    need(task is not None and task[0]==thread and turn is not None and turn[0]==ack['turn_id']
         and turn[1]==body and turn[2] in {'starting','running'}
         and type(turn[3]) in (int,float) and request['not_before']<=turn[3]<=now<request['expires'],
         'claude_delivery_not_current')
    current=transcript_current(transcript,thread,body)
    try:
        parsed=dt.datetime.fromisoformat(current['timestamp'].replace('Z','+00:00'))
        need(parsed.utcoffset() is not None,'claude_transcript_time_invalid')
        timestamp=parsed.timestamp()
    except (KeyError,TypeError,ValueError):raise ClaudeEvidenceError('claude_transcript_time_invalid') from None
    need(turn[3]<=timestamp<=now and timestamp-turn[3]<=300,'claude_transcript_time_invalid')
    local_turn=hook_state.get('turn_id')
    if binding_mode=='pending':
        need(hook_state.get('prompt_sha256')==sha(body)
             and (hook_state.get('admission_status'),hook_state.get('turn_memory_lease')) in
                 {('provisional','provisional'),('delegation-pending','pending-proof')},
             'claude_own_hook_binding_not_current')
    elif binding_mode in {'current','rebind'}:
        need(isinstance(owning_claim,dict) and owning_claim.get('found') and owning_claim.get('state')=='executing'
             and not owning_claim.get('revoked') and owning_claim.get('request_digest')==core.digest(request)
             and owning_claim.get('delivery',{}).get('receiving_turn_id')==turn[0]
             and owning_claim.get('delivery',{}).get('receiving_item_id')==current['uuid']
             and hook_state.get('delegation_operation_id')==request['operation_id']
             and hook_state.get('delegation_receiving_turn_id')==turn[0]
             and hook_state.get('delegation_carrier_sha256')==sha(body)
             and hook_state.get('delegation_admission_sha256')==hook_state.get('prompt_sha256')
             and hook_state.get('delegation_scope_capture',{}).get('own_hook_turn_id')==local_turn
             and (binding_mode=='rebind' and hook_state.get('delegation_rebind_required') is True
                  or binding_mode=='current' and (hook_state.get('admission_status'),hook_state.get('turn_memory_lease')) in
                     {('provisional','provisional'),('ready','live')}),'claude_own_claim_binding_invalid')
    else:raise ClaudeEvidenceError('claude_binding_mode_invalid')
    need(hook_state.get('session_hash')==sha(thread)
         and hook_state.get('prompt_truncation') is False and isinstance(local_turn,str)
         and UUID.fullmatch(local_turn.removeprefix('turn:')) is not None
         and type(hook_state.get('turn_memory_generation')) is int
         and hook_state['turn_memory_generation']>0
         and (payload.get('turn_id') is None or payload['turn_id']==local_turn),
         'claude_own_hook_binding_not_current')
    receiving={'host_id':host,'thread_id':thread,'turn_id':turn[0],'item_id':current['uuid'],'body':body}
    delivery=core.verify_delivery(request,source,receiving)
    return {'status':'verified-cli-delivery-data','request':request,'receiving':receiving,'delivery_receipt':delivery,
        'own_hook_turn_id':local_turn,'own_hook_generation':hook_state['turn_memory_generation'],
        'provider':'claude','native_codex_turn_fabricated':False,'owner_and_controls_verified':False,
        'action_authority':'not-evaluated','task_claimed':False,'memory_binding_staged':False}
