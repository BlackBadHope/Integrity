# SPDX-License-Identifier: BUSL-1.1
"""Deterministic scoring for the separate equal-information context smoke."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import statistics

ROOT=Path(__file__).absolute().parent.parent

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def main(run_id='eff-20261021-smoke-01'):
    assert run_id in {'eff-20261021-smoke-01','eff-20261021-files-01'}
    BASE=ROOT/'evidence'/run_id
    fixtures=json.loads((ROOT/'controller/efficiency-smoke-fixtures.json').read_text(encoding='utf-8'))
    retrieval=json.loads((BASE/'retrieval.json').read_text(encoding='utf-8'))
    model=json.loads((BASE/'model-runs.json').read_text(encoding='utf-8'))
    controller=json.loads((BASE/'controller.json').read_text(encoding='utf-8'))
    is_files=run_id=='eff-20261021-files-01'
    assert controller['NAT_cable']=='OFF' and controller['guest_cleanup']['default_routes']==0
    cases={c['id']:c for c in fixtures['cases']};recalls={c['id']:c for c in retrieval['cases']}
    # Independently regenerate exactly the allowed subject inputs, not its oracle.
    tree=ast.parse((ROOT/'tools/windows_efficiency_smoke.py').read_text(encoding='utf-8'))
    ns={'json':json}
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='prompt')
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<verified-LAB-prompt-builder>','exec'),ns)
    scored=[]
    usage_keys=['input_tokens','cached_input_tokens','cache_write_input_tokens','output_tokens','reasoning_output_tokens']
    for r in model['rows']:
        assert isinstance(r.get('usage'),dict) and all(type(r['usage'].get(k)) is int for k in usage_keys),'Missing usage must remain unknown, never zero'
        c=cases[r['id']];a=r.get('answer',{});available={d['key'] for x in (fixtures['cases'] if is_files else [c]) for d in x['corpus']}
        inp={k:c[k] for k in ['id','task_id','task','corpus','corpus_sha256']}
        inp['capsule']=recalls[c['id']]['recall']
        if is_files:inp['kind']='files'
        expected_prompt=ns['prompt'](inp,r['arm'])
        prompt_verified=hashlib.sha256(expected_prompt.encode()).hexdigest()==r['prompt_sha256']
        cited=a.get('source_keys',[]) if isinstance(a,dict) else []
        format_valid=(isinstance(a,dict) and set(a)=={'state','answer','source_keys'} and a.get('state') in {'COMPLETE','UNKNOWN'}
            and isinstance(a.get('answer'),dict) and isinstance(cited,list) and all(isinstance(k,str) for k in cited) and len(cited)==len(set(cited)))
        valid_sources=isinstance(cited,list) and all(isinstance(k,str) for k in cited) and set(c['required_sources'])<=set(cited)<=available
        correct=(format_valid and a.get('state')=='COMPLETE' and canonical(a.get('answer'))==canonical(c['expected_answer']) and valid_sources)
        # Secondary diagnostic added after collection. Never replaces exact-answer
        # primary scoring or admits an unsuccessful pair to the primary speedup.
        fields_correct=(format_valid and a.get('state')=='COMPLETE' and valid_sources and
            all(k in a['answer'] and canonical(a['answer'][k])==canonical(v) for k,v in c['expected_answer'].items()))
        tools_valid=(r.get('tools_called',0)<=4 and model.get('documents_unchanged') is True) if is_files else r.get('tools_called')==0
        valid=(r['status']=='PROCESS_COMPLETED' and r.get('model_turns')==1 and tools_valid and prompt_verified)
        error_class=None if correct else ('EXTRA_ANSWER_FIELDS' if fields_correct else 'FORMAT_OR_SOURCE_OR_VALUE_ERROR')
        scored.append({**r,'input_independently_regenerated':prompt_verified,'format_valid':format_valid,
            'correct':correct,'requested_fields_correct_secondary':fields_correct,'scoring_error_class':error_class,'valid':valid})
    pairs=[]
    for cid,c in cases.items():
        rows={r['arm']:r for r in scored if r['id']==cid}
        retrieved_keys=[]
        for e in recalls[cid]['recall'].get('events',[]):
            try:retrieved_keys.append(json.loads(e['summary'])['key'])
            except (ValueError,KeyError,TypeError):pass
        entry={'id':cid,'retrieved_required_sources':sorted(set(c['required_sources'])&set(retrieved_keys)),
            'retrieval_source_recall':len(set(c['required_sources'])&set(retrieved_keys))/len(c['required_sources']),
            'all_retrieved_sources_in_common_corpus':set(retrieved_keys)<={d['key'] for x in (fixtures['cases'] if is_files else [c]) for d in x['corpus']}}
        if set(rows)=={'ON','OFF'}:
            off,on=rows['OFF'],rows['ON'];both=all(x['valid'] and x['correct'] for x in [off,on])
            entry.update(OFF_correct=off['correct'],ON_correct=on['correct'],both_successful=both,
                OFF_seconds=off['accounted_latency_seconds'],ON_seconds=on['accounted_latency_seconds'],
                speedup_OFF_div_ON=round(off['accounted_latency_seconds']/on['accounted_latency_seconds'],6) if both else None,
                ON_extra_seconds=round(on['accounted_latency_seconds']-off['accounted_latency_seconds'],4))
        pairs.append(entry)
    totals={}
    for arm in ['OFF','ON']:
        rows=[r for r in scored if r['arm']==arm];usage=[r.get('usage',{}) for r in rows]
        totals[arm]={'runs':len(rows),'valid':sum(r['valid'] for r in rows),'correct':sum(r['correct'] and r['valid'] for r in rows),
            'model_wall_seconds_total':round(sum(r['elapsed_seconds'] for r in rows),4),
            'accounted_latency_seconds_total':round(sum(r['accounted_latency_seconds'] for r in rows),4),
            'input_tokens':sum(u.get('input_tokens',0) for u in usage),'cached_input_tokens':sum(u.get('cached_input_tokens',0) for u in usage),
            'output_tokens':sum(u['output_tokens'] for u in usage),
            'cache_write_input_tokens':sum(u['cache_write_input_tokens'] for u in usage),
            'reasoning_output_tokens':sum(u['reasoning_output_tokens'] for u in usage),
            'tool_calls':sum(r.get('tools_called',0) for r in rows),
            'requested_fields_correct_secondary':sum(r['requested_fields_correct_secondary'] and r['valid'] for r in rows),
            'commands_with_nonzero_exit':sum(x.get('exit_code') not in {0,None} for r in rows for x in r.get('commands',[]))}
        totals[arm]['uncached_input_tokens']=totals[arm]['input_tokens']-totals[arm]['cached_input_tokens']
    runtimes={canonical({k:r.get('runtime_metadata',{}).get(k) for k in ['model','provider','reasoning_effort','cli_version']}) for r in scored}
    successful=[p for p in pairs if p.get('both_successful')]
    result={'schema':'integrity-lab.efficiency-smoke-result.v1','status':'SCORED',
        'source_plane':'CONTROLLER_DELIVERED_REAL_INTEGRITY_READONLY_SNAPSHOT_RECALL','native_end_to_end':False,
        'run_id':retrieval['run_id'],'kind':'files' if is_files else 'context','pairs_planned':4,'model_runs':len(scored),
        'equal_information':all(p['all_retrieved_sources_in_common_corpus'] for p in pairs),
        'runtime_metadata_matched':len(runtimes)==1 and all(r.get('runtime_metadata',{}).get('model') and r.get('runtime_metadata',{}).get('cli_version') for r in scored),'runtimes':[json.loads(x) for x in runtimes],
        'totals':totals,'pairs':pairs,'successful_pairs_for_latency':len(successful),
        'median_paired_speedup_OFF_div_ON':statistics.median(p['speedup_OFF_div_ON'] for p in successful) if successful else None,
        'latency_accounting':'CLI process wall time plus measured in-process Integrity initialization/snapshot/recall for ON; provisioning, SSH batch transport and orchestration excluded',
        'secondary_scoring':'Requested-field correctness is a post-collection diagnostic only; exact-answer primary scoring is unchanged',
        'limitations':['Four pairs with one repetition; no statistical significance claim','Synthetic context/file search only; no coding tasks',
            'Full identical corpus available in both arms (prompt or files); ON adds unfiltered actual recall','Native owner/lifecycle head guard remains unresolved; this is not Native e2e',
            'Shared account cloud-wide authorization boundary is not proven','Prices are not estimated; token counts and cached counts reported separately',
            'Cache/load/network are not experimentally controlled; counterbalanced order and single repetition cannot remove these effects',
            'Files Q1 was evaluated on the same fixtures after observing Q0; no held-out query validation and no causal cross-stratum comparison'],
        'catalog_unchanged':retrieval['source_catalog_unchanged'],'cleanup':controller['guest_cleanup'],'NAT_cable':controller['NAT_cable'],
        'rows':scored}
    result['all_pairs_complete_valid']=len(scored)==8 and all(r['valid'] for r in scored) and result['runtime_metadata_matched'] and result['equal_information']
    (BASE/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['status','all_pairs_complete_valid','totals','pairs','median_paired_speedup_OFF_div_ON']},ensure_ascii=False))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run-id',default='eff-20261021-smoke-01')
    main(parser.parse_args().run_id)
