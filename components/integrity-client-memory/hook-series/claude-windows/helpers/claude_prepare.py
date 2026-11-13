"""Read-only owner preparation with actual enrolled idle CLI target evidence."""
import ast
import hashlib
from contextlib import closing
from types import FunctionType
import claude_delivery_evidence as local

BEGIN='BEGIN_INTEGRITY_CLAUDE_DELEGATION_PREPARE'
END='END_INTEGRITY_CLAUDE_DELEGATION_PREPARE'

def arguments(prompt,thread,profile):
    local.need(thread==profile['target_thread_id'] and isinstance(prompt,str)
        and prompt.startswith(BEGIN+'\n') and prompt.endswith('\n'+END),'claude_preparation_recipe_invalid')
    value=local.strict_json(prompt[len(BEGIN)+1:-len(END)-1])
    local.need(isinstance(value,dict) and set(value)<={'task','owner_thread_id','owner_message_id','owner_turn_id','owner_item_id'}
        and isinstance(value.get('task'),str) and value['task'].strip(),'claude_preparation_arguments_invalid')
    return value

def prepare(profile,core,native,reader,**arguments):
    local.need(set(arguments)<={'task','owner_thread_id','owner_message_id','owner_turn_id','owner_item_id'},
               'claude_preparation_arguments_invalid')
    target=profile['target_thread_id']
    with closing(local.readonly(profile['cli_ledger'])) as db:
        task=db.execute('SELECT session_id FROM tasks WHERE id=?',(target,)).fetchone()
        latest=db.execute('SELECT id,status FROM turns WHERE task_id=? ORDER BY created DESC LIMIT 1',(target,)).fetchone()
    local.need(task is not None and task[0]==target and latest is not None and latest[1] in {'completed','failed','interrupted'},
               'claude_preparation_target_not_idle')
    frontier=core.read_frontier(profile['ledger_path'],profile['source_thread_id'])
    local.need(frontier is not None and frontier['source_provider']=='codex'
        and frontier['host_id']==profile['source_host_id'] and frontier['source_room_id']==profile['source_room_id'],
        'claude_source_not_ready')
    # Same authenticated live owner parser and neutral Core builder. Replace
    # only the Codex target-head check with the real CLI registry/idle check;
    # no synthetic Native page or UUID is manufactured.
    verified=getattr(native,'__verified_source_bytes__',None)
    local.need(isinstance(verified,bytes) and hashlib.sha256(verified).hexdigest()==profile['adapter_sha256'],
               'claude_prepare_source_pin_invalid')
    tree=ast.parse(verified)
    functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prepare_delegation']
    local.need(len(functions)==1,'claude_prepare_source_contract_changed')
    function=functions[0];original=ast.Module(body=[function],type_ignores=[])
    removed=[];kept=[]
    for node in function.body:
        is_assignment=isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
        name=node.targets[0].id if is_assignment else None
        if name in {'native_host','target'}:removed.append(name);continue
        if (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name)
           and node.value.func.id=='check_page' and node.value.args and isinstance(node.value.args[0],ast.Name)
           and node.value.args[0].id=='target'):removed.append('check_page');continue
        kept.append(node)
    local.need(removed==['target','check_page'],'claude_prepare_source_contract_changed')
    function.body=kept;namespace=dict(native.prepare_delegation.__globals__)
    exec(compile(ast.fix_missing_locations(original),'<pinned-claude-prepare>','exec'),namespace)
    result=namespace['prepare_delegation'](profile,core,reader,target_thread_id=target,**arguments)
    local.need(len(result['frame'])<=8000,'claude_preparation_frame_oversized')
    result.update(provider='claude',cli_target_evidence={'thread_id':target,'latest_turn_id':latest[0],'status':latest[1]},
                  cli_start_performed=False,native_send_performed=False)
    return result
