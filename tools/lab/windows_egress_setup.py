# SPDX-License-Identifier: BUSL-1.1
"""Provision only the LAB guest HTTPS proxy and guest-local proxy preferences."""
from pathlib import Path
import argparse,base64,hashlib,json,os,shlex,ssl,subprocess,sys,urllib.request,urllib.error
sys.path.insert(0,str(Path(__file__).resolve().parent))
from windows_native_binding import remote,successful,save,CONTROL,ROOT
import lab_config


def proxy_url():
    return 'http://'+lab_config.setting('network.linux_guest_ip')+':'+str(lab_config.setting('network.proxy_port'))


def prepare():
    body=(CONTROL/'lab_egress_proxy.py').read_bytes()
    source=r'''
from pathlib import Path
import base64,hashlib,json,os,socket
assert socket.gethostname()==@LINUX_HOSTNAME@ and os.geteuid()==0
body=base64.b64decode(PAYLOAD)
target=Path('/opt/integrity-lab/tools/lab_egress_proxy.py')
network=Path('/etc/netplan/70-integrity-lab-egress.yaml')
net=b''' + '"""' + '''network:
  version: 2
  ethernets:
    egress0:
      match:
        macaddress: "@EGRESS_MAC@"
      set-name: egress0
      dhcp4: true
      dhcp6: false
      accept-ra: false
      link-local: []
      dhcp4-overrides:
        use-dns: false
      nameservers:
        addresses: [@NAMESERVERS@]
''' + '"""' + r'''
for p,data,mode in [(target,body,0o644),(network,net,0o600)]:
    if p.exists():assert p.is_file() and not p.is_symlink() and p.read_bytes()==data, 'Unexpected existing LAB egress artifact'
    else:p.write_bytes(data)
    p.chmod(mode);os.chown(p,0,0)
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='0'
print(json.dumps({'status':'PREPARED_NOT_NETWORKED','proxy_sha256':hashlib.sha256(body).hexdigest(),'IPv4_forwarding':False,'autostart':False}))
'''
    source=source.replace('PAYLOAD',repr(base64.b64encode(body).decode('ascii')))
    source=lab_config.fill(source,LINUX_HOSTNAME=lab_config.setting('vms.linux.hostname'))
    source=lab_config.fill(source,quote=str,EGRESS_MAC=lab_config.mac(lab_config.setting('vms.linux.egress_mac')),
        NAMESERVERS=', '.join(lab_config.setting('egress_network.nameservers')))
    compile(source,'LAB-egress-provision','exec')
    value=json.loads(successful(remote('sudo -n /usr/bin/python3 -I -B -',source)))
    save('egress-prepared.json',value)


def start(max_seconds=3600):
    if type(max_seconds) is not int or not 60 <= max_seconds <= 3600:
        raise ValueError('Bounded LAB proxy runtime required')
    # Transient service only; no enable, boot trigger, package installation or TLS interception.
    deny=' '.join(lab_config.setting('egress_network.kernel_deny_networks'))
    if not deny:raise LookupError('lab configuration key egress_network.kernel_deny_networks must not be empty')
    args=['systemd-run','--unit=integrity-lab-egress','--collect',
          '-p','DynamicUser=yes','-p','NoNewPrivileges=yes','-p','PrivateDevices=yes','-p','PrivateTmp=yes',
          '-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','ProtectKernelTunables=yes',
          '-p','ProtectKernelModules=yes','-p','ProtectControlGroups=yes','-p','RestrictSUIDSGID=yes',
          '-p','CapabilityBoundingSet=','-p','RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
          '-p','RestrictNamespaces=yes','-p','LockPersonality=yes','-p','TasksMax=24',
          '-p','MemoryMax=160M','-p','RuntimeMaxSec='+str(max_seconds),'-p','IPAccounting=yes',
          '-p','IPAddressDeny='+deny,
          '-p','IPAddressAllow='+lab_config.setting('network.windows_guest_ip')+'/32 127.0.0.53/32',
          '/usr/bin/python3','-I','-B','/opt/integrity-lab/tools/lab_egress_proxy.py',
          '--listen',lab_config.setting('network.linux_guest_ip'),'--port',str(lab_config.setting('network.proxy_port')),
          '--client',lab_config.setting('network.windows_guest_ip')]
    successful(remote('sudo -n '+shlex.join(args)))
    state=successful(remote('systemctl is-active integrity-lab-egress.service')).strip()
    assert state=='active'
    save('egress-service.json',{'status':'ACTIVE_TRANSIENT_PROXY','runtime_max_seconds':max_seconds,'autostart':False,
        'TLS_interception':False,'private_destination_kernel_filter':True,'Windows_default_route':'ABSENT',
        'host_firewall_changes':0,'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def probe():
    # Force the explicit proxy for this technical probe, including localhost denials.
    os.environ['HTTPS_PROXY']=proxy_url()
    os.environ['NO_PROXY']=''
    os.environ['no_proxy']=''
    # Fresh offline Windows has a cold CA store. Use the public Mozilla bundle
    # already shipped in this installed pip; never disable certificate checking.
    import pip._vendor.certifi
    ca=Path(pip._vendor.certifi.where())
    context=ssl.create_default_context(cafile=str(ca))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({'https':proxy_url()}),
                                      urllib.request.HTTPSHandler(context=context))
    rows=[]
    allowed_url=lab_config.setting('egress_network.probe_allowed_url')
    private_url='https://'+lab_config.setting('egress_network.probe_private_address')+'/'
    for url,allowed in [(allowed_url,True),('https://example.com/',False),('https://127.0.0.1/',False),(private_url,False)]:
        try:
            with opener.open(url,timeout=20) as response:status=response.status
            result='TLS_RESPONSE' if allowed else 'FAIL_UNEXPECTED_ACCESS'
        except urllib.error.HTTPError as e:
            status=e.code;result='TLS_RESPONSE' if allowed else 'FAIL_UNEXPECTED_ACCESS'
        except urllib.error.URLError as e:
            status=None
            if not allowed and '403 Forbidden' in str(e.reason):result='POLICY_DENIED'
            else:result='FAIL_TLS_OR_TRANSPORT'
        rows.append({'destination':url.split('/')[2],'expected_allowed':allowed,'result':result,'http_status':status})
    report={'status':'PASS' if all(x['result']==('TLS_RESPONSE' if x['expected_allowed'] else 'POLICY_DENIED') for x in rows) else 'FAIL',
        'checks':rows,'auth_requests':0,'credentials_read':False,'models':'NOT_RUN','agents':'NOT_RUN'}
    report['TLS_verification']={'enabled':True,'CA_source':'Installed pip Mozilla CA bundle','CA_sha256':hashlib.sha256(ca.read_bytes()).hexdigest(),
                               'Windows_trust_store_modified':False}
    previous=ROOT/'evidence/egress-probe.json'
    if previous.exists() and json.loads(previous.read_text())['status']=='FAIL':
        backup=ROOT/'evidence/egress-probe-before-public-CA-bundle.json'
        if not backup.exists():backup.write_bytes(previous.read_bytes())
    save('egress-probe.json',report)
    assert report['status']=='PASS'


if __name__=='__main__':
    if os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):raise PermissionError('LAB guest only')
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['prepare','start','probe','shutdown']);args=p.parse_args()
    if args.stage=='prepare':prepare()
    elif args.stage=='start':start()
    elif args.stage=='probe':probe()
    else:
        # Graceful Linux shutdown, no raw poweroff or forced snapshot restore.
        remote('sudo -n /usr/bin/systemctl poweroff',timeout=20)
        print(json.dumps({'status':'LAB_LINUX_GRACEFUL_SHUTDOWN_REQUESTED'}))
