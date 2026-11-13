# SPDX-License-Identifier: BUSL-1.1
"""Select the published Windows envelope matching the published broker API.

Only source ASTs are inspected. No real refs, model calls or ledger mutations.
"""
from pathlib import Path
import ast
import hashlib
import json

ROOT=Path(__file__).absolute().parent.parent
RES=ROOT/'runtime/integrity-next-source/components/integrity-client-memory/src/integrity_client_memory/resources'
OUT=ROOT/'controller/native-envelope-candidate-v3'

def main():
    broker=ast.parse((RES/'windows/integrity-client-turn-broker.py').read_text(encoding='utf-8'))
    public_raw=(RES/'windows/integrity_client_turn_envelope.py').read_bytes()
    source=public_raw.decode()
    old_state='''    base = (Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))/'integrity-memory/state'
            if state_root is None else state_root)'''
    old_resume='    base=Path(os.environ.get("CODEX_HOME",str(Path.home()/".codex")))/"integrity-memory/state"'
    assert source.count(old_state)==source.count(old_resume)==1
    source=source.replace(old_state,'    base = Path(_integrity_value("private_state_root")) if state_root is None else state_root')
    source=source.replace(old_resume,'    base=Path(_integrity_value("private_state_root"))')
    raw=source.encode()
    tree=ast.parse(raw)
    old=ast.parse((RES/'windows/native/integrity_client_turn_envelope.py').read_bytes())
    def names(t):
        result=set()
        for n in t.body:
            if isinstance(n,(ast.FunctionDef,ast.ClassDef)):result.add(n.name)
            if isinstance(n,ast.Assign):
                result.update(x.id for x in n.targets if isinstance(x,ast.Name))
        return result
    required={n.attr for n in ast.walk(broker) if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and n.value.id=='turn_envelope'}
    missing=sorted(required-names(old));remaining=sorted(required-names(tree))
    assert 'bind_resume_identity_from_claim' in missing and not remaining
    # Claim/identity guards stay unchanged; only the two fixed locators change.
    functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    bind=ast.get_source_segment(raw.decode(),functions['bind_resume_identity_from_claim'])
    assert all(x in bind for x in ['_require_claim','_unprotect','_native_owning_head','_resume_successor_join','_RESUME_CLAIM_OWNER'])
    assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {'stage','arm','issue_owning_lifecycle'} for n in ast.walk(functions['bind_resume_identity_from_claim']))
    OUT.mkdir(exist_ok=True)
    dest=OUT/'integrity_client_turn_envelope.py'
    if dest.exists():assert dest.read_bytes()==raw
    else:dest.write_bytes(raw)
    report={'status':'PASS_SOURCE_INTERFACE_GATE','broker_envelope_symbols':len(required),
        'old_native_missing':missing,'candidate_missing':remaining,'candidate_sha256':hashlib.sha256(raw).hexdigest(),
        'source':str(RES/'windows/integrity_client_turn_envelope.py'),'public_source_sha256':hashlib.sha256(public_raw).hexdigest(),
        'candidate_is_unmodified_public_source':False,'changes':['Use compiler-pinned private_state_root in both owning state readers'],
        'private_claim_DPAPI_current_head_and_supersession_guards':'PRESERVED',
        'owner_identity_fabricated':False,'live_acceptance':'NOT_EVALUATED_BY_SOURCE_GATE'}
    (OUT/'review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))

if __name__=='__main__':main()
