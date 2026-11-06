# SPDX-License-Identifier: Apache-2.0
"""Linux owning Native head, never Windows.

Two custody modes; the generated profile selects one, the model never does.

* ``system`` (default when no mode is configured): the existing verified
  root-owned factory and Unix owner socket.
* ``user``: the same-uid head published by the pinned hook runner, accepted
  only while the caller descends from the live pinned vendor process
  (see ``linux_user_native``).
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from integrity_client_memory.configuration import read_config as _integrity_read_config
import hashlib,importlib.util,json,os,re,stat,time
from pathlib import Path
UUID=re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
def need(ok,code):
    if not ok:raise ValueError(code)
def custody_mode():
    mode=_integrity_read_config().get('values',{}).get('linux_native_mode','system')
    need(mode in {'system','user'},'linux_native_mode_invalid')
    return mode
def user_custody_caller_proven():
    """Profile-selected user custody with a live ancestor running the pinned vendor.

    Codex app-server daemon hooks and their brokers get no CODEX_THREAD_ID; this
    process-ancestry proof (never model input) stands in for it, nothing else.
    """
    if os.name!='posix' or custody_mode()!='user':return False
    from integrity_client_memory import linux_user_native
    try:
        linux_user_native.find_vendor_ancestor(_integrity_value('linux_native_executable'),
            _integrity_value('linux_native_executable_sha256'))
    except (OSError,ValueError):return False
    return True
def verified_current_head(thread_id):
    """Read-only primitive; no registration, lease, claim, append or execution."""
    need(os.name=='posix' and UUID.fullmatch(thread_id),'linux_native_subject_invalid')
    if custody_mode()=='user':
        from integrity_client_memory import linux_user_native
        return linux_user_native.verified_head(Path(_integrity_value('linux_native_head_root')),thread_id,
            _integrity_value('linux_native_executable'),_integrity_value('linux_native_executable_sha256'))
    root=Path(_integrity_value('path_421d7209bec4'));factory_sha=_integrity_value('pin_49aaeb94d0ae')
    path=root/'linux_runtime_factory.py';details=path.lstat()
    need(not path.is_symlink() and stat.S_ISREG(details.st_mode) and details.st_uid==0
        and not stat.S_IMODE(details.st_mode)&0o022,'linux_native_factory_custody_invalid')
    raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==factory_sha,'linux_native_factory_pin_changed')
    spec=importlib.util.spec_from_file_location('owning_linux_verified_factory',path)
    factory=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),factory.__dict__)
    profile=json.loads(factory.protected_bytes(factory.CONFIG,private=True))
    sdk=factory.UnixOwnerSDK(thread_id,time.monotonic()+18,profile)
    try:
        metadata=sdk.request('thread/read',{'threadId':thread_id,'includeTurns':False},6)
        need(metadata.get('thread',{}).get('id')==thread_id,'linux_native_thread_mismatch')
        # Verify the current subject using metadata; never load turn contents here.
        # Full item provenance is a separate read and remains unchanged.
        page=sdk.request('thread/turns/list',{'threadId':thread_id,'limit':1,
            'sortDirection':'desc','itemsView':'notLoaded'},10)
        rows=page.get('data');need(isinstance(rows,list) and len(rows)==1,'linux_native_head_missing')
        turn=rows[0]
        need(UUID.fullmatch(str(turn.get('id'))) and turn.get('status') in
            {'inProgress','completed','failed','interrupted'} and not turn.get('truncated')
            and not turn.get('itemsTruncated'),'linux_native_head_invalid')
        return {'id':turn['id'],'status':turn['status']}
    finally:sdk.close()
def current_owning_turn(thread_id):
    # A user-custody MCP broker does not inherit the per-command CODEX_THREAD_ID;
    # its proof is the live pinned ancestor, so only a conflicting value is refused.
    caller=os.environ.get('CODEX_THREAD_ID')
    if custody_mode()=='user':need(caller in (None,thread_id),'linux_native_caller_mismatch')
    else:need(caller==thread_id,'linux_native_caller_mismatch')
    return verified_current_head(thread_id)
