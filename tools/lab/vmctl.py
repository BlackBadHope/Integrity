# SPDX-License-Identifier: BUSL-1.1
"""Manage only the two newly authorized LAB VMs; no model/benchmark launcher."""
from pathlib import Path
import argparse, ctypes, json, shutil, subprocess, sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config
ROOT=Path(__file__).absolute().parent.parent
VBOX=Path(lab_config.setting('host.vboxmanage'))
BASE=ROOT/'runtime/vms'
LAYOUT=ROOT/'controller/vm-layout.json'
WINDOWS=lab_config.setting('vms.windows.name')
LINUX=lab_config.setting('vms.linux.name')
VMS={WINDOWS:{'os':'Windows11_64','memory_mib':4096,'cpus':3,'disk_mib':65536,'ip':lab_config.setting('network.windows_guest_ip')},
     LINUX:{'os':'Ubuntu_64','memory_mib':1536,'cpus':1,'disk_mib':24576,'ip':lab_config.setting('network.linux_guest_ip')}}
INTNET=lab_config.setting('network.internal_network')
UUIDS={WINDOWS:lab_config.setting('vms.windows.uuid'),LINUX:lab_config.setting('vms.linux.uuid')}
EGRESS_MAC=lab_config.mac(lab_config.setting('vms.linux.egress_mac'),'vbox')
def call(args):
    p=subprocess.run([str(VBOX),*map(str,args)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    if p.returncode:raise RuntimeError('VBox command failed: '+str(args[:3])+' '+p.stderr[-600:])
    return p.stdout
def info(name):
    if name not in VMS:raise ValueError('foreign VM')
    return dict(line.split('=',1) for line in call(['showvminfo',name,'--machinereadable']).splitlines() if '=' in line)
def status():
    rows=[]
    for name in VMS:
        d=info(name)
        rows.append({k:d.get(k) for k in ['name','UUID','CfgFile','VMState','memory','cpus','firmware','nic1','intnet1','nic2','clipboard','draganddrop','SharedFolderNameMachineMapping1']})
    return rows

def owned_info(name):
    raw=info(name)
    def value(key):
        v=raw.get(key)
        return json.loads(v) if v and v.startswith('"') else v
    if value('UUID')!=UUIDS[name] or not Path(value('CfgFile')).is_relative_to(BASE):
        raise PermissionError('VM identity/configuration root mismatch')
    if value('nic1')!='intnet' or value('intnet1')!=INTNET:
        raise PermissionError('LAB-only network binding changed')
    extra_start=2
    if name==LINUX and value('nic2')!='none':
        # Account-login phase with a separately authorized egress policy: Windows stays internal only.
        policy=json.loads((ROOT/'controller/egress.json').read_text(encoding='utf-8'))
        if (policy.get('enabled') is not True or policy.get('mode')!='LINUX_HTTPS_PROXY_ONLY'
            or policy.get('VM_UUID')!=UUIDS[name] or value('nic2')!='nat'
            or value('macaddress2')!=EGRESS_MAC
            or any(k.startswith('Forwarding') or k.startswith('natpf') for k in raw)):
            raise PermissionError('Unexpected LAB egress binding')
        extra_start=3
    if any(value('nic'+str(n))!='none' for n in range(extra_start,9)):
        raise PermissionError('Unexpected additional NIC')
    if value('clipboard')!='disabled' or value('draganddrop')!='disabled' or any(k.startswith('SharedFolderName') for k in raw):
        raise PermissionError('Unexpected host sharing')
    return raw

def start(name):
    raw=owned_info(name)
    if json.loads(raw['VMState']) not in {'poweroff','saved'}:raise RuntimeError('VM is already started or not in an approved stopped state')
    class Memory(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong),('total',ctypes.c_ulonglong),('available',ctypes.c_ulonglong),
                  ('total_page',ctypes.c_ulonglong),('available_page',ctypes.c_ulonglong),('total_virtual',ctypes.c_ulonglong),
                  ('available_virtual',ctypes.c_ulonglong),('available_extended',ctypes.c_ulonglong)]
    memory=Memory();memory.length=ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):raise OSError('Cannot read available memory')
    available=memory.available//(1024*1024);requested=int(raw['memory']);reserve=3072
    free=shutil.disk_usage(ROOT).free
    report={'VM':name,'UUID':UUIDS[name],'available_mib_before_start':available,'requested_mib':requested,'host_reserve_mib':reserve,
            'D_free_gib':round(free/(1024**3),2),'network':'internal_plus_proxy_egress' if json.loads(raw['nic2'])=='nat' else 'internal_only','agents':'NOT_RUN','benchmarks':'NOT_RUN'}
    if available < requested+reserve:raise RuntimeError('RAM gate blocked: '+json.dumps(report))
    if free < 20*(1024**3):raise RuntimeError('Disk reserve gate blocked')
    result=call(['startvm',UUIDS[name],'--type','headless'])
    report['start_result']=result.strip()
    (ROOT/'evidence'/('VM-START-'+name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
def create():
    if LAYOUT.exists():raise FileExistsError('VM layout exists; inspect before mutation')
    existing=call(['list','vms'])
    if any('"'+x+'"' in existing for x in VMS):raise FileExistsError('LAB VM already registered')
    sys.path.insert(0,str(ROOT/'runtime/venv/Lib/site-packages'))
    from integrity_guardian._windows_files import create_private_directory_tree
    BASE.parent.mkdir(parents=True,exist_ok=True)
    create_private_directory_tree(BASE)
    (ROOT/'runtime/media').mkdir(exist_ok=True)
    (ROOT/'evidence/VM-HOST-PREIMAGE.txt').write_text(existing,encoding='utf-8')
    for name,cfg in VMS.items():
        call(['createvm','--name',name,'--basefolder',BASE,'--ostype',cfg['os'],'--platform-architecture','x86','--register'])
        options=['modifyvm',name,'--groups','/IntegrityLAB','--memory',cfg['memory_mib'],'--cpus',cfg['cpus'],'--ioapic','on',
                 '--nic1','intnet','--intnet1',INTNET,'--nic-type1','82540EM','--nic-promisc1','deny',
                 '--clipboard-mode','disabled','--drag-and-drop','disabled','--audio-enabled','off','--vrde','off','--teleporter','off',
                 '--usb-ohci','off','--usb-ehci','off','--usb-xhci','off','--autostart-enabled','off','--accelerate-3d','off']
        for n in range(2,9):options+=['--nic'+str(n),'none']
        if name==WINDOWS:options+=['--firmware','efi','--tpm-type','2.0','--graphicscontroller','vboxsvga','--vram','128']
        else:options+=['--firmware','bios','--graphicscontroller','vmsvga','--vram','16','--uart1','0x3f8','4','--uart-mode1','file',ROOT/'evidence/linux-serial.log']
        call(options)
        call(['storagectl',name,'--name','SATA','--add','sata','--controller','IntelAhci','--portcount','4','--bootable','on'])
        if name==WINDOWS:
            disk=BASE/name/'Windows.vdi'
            call(['createmedium','disk','--filename',disk,'--size',cfg['disk_mib'],'--format','VDI','--variant','Standard'])
            call(['storageattach',name,'--storagectl','SATA','--port','0','--device','0','--type','hdd','--medium',disk])
        call(['modifyvm',name,'--boot1','disk','--boot2','dvd','--boot3','none','--boot4','none'])
    data={'schema':'integrity-lab.vm-layout.v1','hypervisor':str(VBOX),'base':str(BASE),'internal_network':INTNET,'mask':24,
          'VMs':VMS,'created':status(),'model_runs_allowed':False,'benchmarks_allowed':False,'egress':'NOT_CONFIGURED_INTERNAL_ONLY',
          'Windows_activation':'NOT_REQUESTED_NO_KEY','preflight':'STATIC_ONLY_OS_NOT_INSTALLED'}
    LAYOUT.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(data))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['create','status','start']);parser.add_argument('--name',choices=list(VMS));args=parser.parse_args()
    if args.action=='create':create()
    elif args.action=='start':
        if not args.name:parser.error('start requires --name')
        start(args.name)
    else:print(json.dumps(status()))
