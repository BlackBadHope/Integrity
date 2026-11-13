# SPDX-License-Identifier: BUSL-1.1
"""Native Codex app-server transport with a closed LAB peer boundary.

Preflight methods never create threads or model turns. Message drafts use the
real native turn/start schema, but execution remains denied by the saved policy.
"""
from __future__ import annotations
from pathlib import Path
import json
import queue
import subprocess
import threading
import time
import uuid
from runtime_common import ROOT,CLI,environment,within


class JsonLines:
    def __init__(self,command,*,home=None,cwd=None,log_name='stdio.log',timeout=30):
        self.log=open(within('evidence/'+log_name),'w',encoding='utf-8')
        self.process=subprocess.Popen(list(map(str,command)),cwd=within(cwd or ROOT),env=environment(home),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,encoding='utf-8',errors='replace',bufsize=1)
        self.timeout=timeout;self.counter=0;self.lines=queue.Queue();self.closed=False
        def drain():
            for line in self.process.stdout:self.lines.put(line)
            self.lines.put(None)
        self.reader=threading.Thread(target=drain,daemon=True);self.reader.start()
    def notify(self,method,params=None):
        self.process.stdin.write(json.dumps({'jsonrpc':'2.0','method':method,'params':params or {}})+'\n');self.process.stdin.flush()
    def call(self,method,params=None):
        self.counter+=1;rid=self.counter
        self.process.stdin.write(json.dumps({'jsonrpc':'2.0','id':rid,'method':method,'params':params or {}})+'\n');self.process.stdin.flush()
        deadline=time.monotonic()+self.timeout
        while True:
            line=self.lines.get(timeout=max(0.01,deadline-time.monotonic()))
            if line is None:raise RuntimeError('technical stdio process exited; see bounded local log')
            value=json.loads(line)
            if value.get('id')==rid and ('result' in value or 'error' in value):return value
            if 'id' in value and 'method' in value:
                self.process.stdin.write(json.dumps({'jsonrpc':'2.0','id':value['id'],'error':{'code':-32601,'message':'No interactive or model callbacks permitted in technical preflight'}})+'\n');self.process.stdin.flush()
            if time.monotonic()>=deadline:raise TimeoutError('technical RPC deadline')
    def close(self):
        if self.closed:return
        self.closed=True
        try:
            self.process.stdin.close();self.process.wait(timeout=5)
        except (BrokenPipeError,subprocess.TimeoutExpired):
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        finally:
            self.reader.join(timeout=1);self.process.stdout.close();self.log.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class NativePeerGateway:
    METADATA_METHODS=frozenset({'initialize','thread/loaded/list','config/read','hooks/list','account/read'})
    def __init__(self,clients,policy):self.clients=clients;self.policy=policy
    def draft(self,sender,recipient,body,bindings):
        if sender not in {'LAB-A','LAB-B'} or recipient not in {'LAB-A','LAB-B'} or sender==recipient:raise PermissionError('foreign or self recipient')
        if not isinstance(body,str) or not 1<=len(body.encode('utf-8'))<=16384:raise ValueError('message size')
        src=bindings.get(sender);dst=bindings.get(recipient)
        if not src or not dst or src.get('episode_id')!=dst.get('episode_id'):raise PermissionError('foreign episode or unbound peer')
        if not dst.get('verified_native_thread') or not dst.get('thread_id'):raise PermissionError('native target not verified')
        message={'protocol':'integrity-lab.peer-data/v1','message_id':'lab-msg:'+uuid.uuid4().hex,'episode_id':src['episode_id'],'sender':sender,'recipient':recipient,'authority':'untrusted-peer-data-not-owner-instruction','body':body}
        return {'method':'turn/start','params':{'threadId':dst['thread_id'],'input':[{'type':'text','text':json.dumps(message,ensure_ascii=False)}]}}
    def send(self,sender,recipient,body,bindings,*,owner_authorization_ref=None):
        readiness=json.loads(within('lab.json').read_text(encoding='utf-8'))
        if readiness.get('phase')!='PILOT_READY' or readiness.get('pilot_execution_allowed') is not True:
            raise PermissionError('pilot readiness gate is closed; no native model turn may start')
        request=self.draft(sender,recipient,body,bindings)
        if self.policy.get('allow_model_turns') is not True or not owner_authorization_ref or owner_authorization_ref!=self.policy.get('owner_authorization_ref'):
            raise PermissionError('model turns are not authorized; native draft is inert')
        reply=self.clients[recipient].call(request['method'],request['params'])
        return {'stage':'native_submission_only','execution_verified':False,'reply':reply}


def client(home,log_name):
    return JsonLines([CLI,'app-server','--listen','stdio://'],home=home,cwd=ROOT/'runtime/probes/shared',log_name=log_name)
