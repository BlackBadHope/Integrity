# SPDX-License-Identifier: BUSL-1.1
"""Run only explicit technical preflight stages inside the two-VM LAB."""
import argparse
import json

from windows_guest_control import ROOT, copy_config, copy_to, powershell, run
import lab_config

CONTROL_ACL = r'''
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne @WINDOWS_HOSTNAME@){throw 'Wrong guest'}
$path='C:\IntegrityLAB\control\preflight-labadmin'
New-Item -ItemType Directory -Path $path -Force | Out-Null
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed=@($me.Value,'S-1-5-18','S-1-5-32-544')
$acl=Get-Acl -LiteralPath $path
$outside=@($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed })
if(-not $acl.AreAccessRulesProtected -or $outside.Count) {
 # Preserve owner/group/SACL; modify only the DACL of this user-owned LAB folder.
 $acl.SetAccessRuleProtection($true,$false)
 foreach($rule in @($acl.Access)) {$acl.RemoveAccessRuleSpecific($rule)}
 foreach($sid in $allowed) {
  $id=[Security.Principal.SecurityIdentifier]::new($sid)
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $path -AclObject $acl
}
$actual=Get-Acl -LiteralPath $path
$unexpected=@($actual.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed })
if(-not $actual.AreAccessRulesProtected -or $unexpected.Count){throw 'Guest control ACL readback failed'}
@{schema='integrity-lab.guest-control-acl.v1';status='PASS';inherited_access_disabled=$true;unexpected_principals=0} | ConvertTo-Json -Compress
'''


def guest_name():
    return lab_config.ps_quote(lab_config.setting('vms.windows.hostname'))


def require(result):
    if result.returncode:
        raise RuntimeError('Guest stage failed: '+result.stderr[-1200:])
    return result.stdout.strip().lstrip('\ufeff')


def collect(name, target):
    if name not in {'native-preflight.json', 'sandbox-preflight.json', 'cross-vm.json', 'preflight.json', 'runtime.json', 'linux-readback.json', 'elevated-setup.json',
                    'native-provision.json','mcp-os-sandbox.json','native-transport.json','native-profiles.json',
                    'native-lifecycle-guards.json','native-desktop-host.json','native-ledger-bootstrap.json','native-isolated-coverage.json',
                    'account-isolation-policy.json','account-isolation-hardened.json','account-isolation-config-readback.json','account-native-tool-policy.json','account-desktop-final-readback.json','account-auth-sandbox.json',
                    'account-proxy.json','account-proxy-readback.json','egress-prepared.json','egress-service.json',
                    'egress-probe.json','egress-probe-before-public-CA-bundle.json','egress-kernel-policy.json'}:
        raise PermissionError('Unexpected evidence')
    raw = require(powershell("Get-Content -LiteralPath 'C:\\IntegrityLAB\\evidence\\"+name+"' -Raw"))
    report = json.loads(raw)
    (ROOT/'evidence'/target).write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('stage', choices=['metadata', 'sandbox', 'prepare-sandbox', 'cross-vm', 'linux-readback', 'shutdown',
                                  'native-provision','native-isolation','native-binding','native-profiles','native-guards','native-host','native-ledgers','native-coverage'])
    p.add_argument('--sandbox-implementation',choices=['mxc','elevated'],default='mxc')
    args = p.parse_args()
    binding = json.loads((ROOT/'evidence/WINDOWS-INDEPENDENT-READBACK.json').read_text())
    if binding['status'] != 'PASS':
        raise RuntimeError('Independent guest identity/setup readback required')
    if args.stage.startswith('native-'):
        stages={'native-provision':('provision','native-provision.json','NATIVE-MCP-PROVISION.json'),
                'native-isolation':('sandbox','mcp-os-sandbox.json','NATIVE-MCP-OS-ISOLATION.json'),
                'native-binding':('bindings','native-transport.json','NATIVE-MCP-TRANSPORT.json'),
                'native-profiles':('profiles','native-profiles.json','NATIVE-GUEST-PROFILES.json'),
                'native-guards':('guards','native-lifecycle-guards.json','NATIVE-LIFECYCLE-GUARDS.json'),
                'native-host':('host','native-desktop-host.json','NATIVE-DESKTOP-HOST.json'),
                'native-ledgers':('bootstrap_ledgers','native-ledger-bootstrap.json','NATIVE-LEDGER-BOOTSTRAP.json'),
                'native-coverage':('coverage','native-isolated-coverage.json','NATIVE-ISOLATED-COVERAGE.json')}
        if args.stage=='native-provision':
            copy_config()
            for filename in ['windows_native_binding.py','linux_mcp_sandbox_setup.py']:
                copy_to(ROOT/'tools'/filename,'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+filename)
        stage,name,target=stages[args.stage]
        result=run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe',[
            '-I','-B',r'C:\IntegrityLAB\control\preflight-labadmin\windows_native_binding.py',stage],timeout=180)
        try:
            report=collect(name,target)
            print(json.dumps(report))
        except Exception:
            require(result)
            raise
        require(result)
        return
    if args.stage == 'shutdown':
        print(require(powershell("if($env:COMPUTERNAME -ne "+guest_name()+"){throw 'Wrong guest'}; shutdown.exe /s /t 5; 'LAB_GUEST_SHUTDOWN_REQUESTED'")))
        return
    if args.stage == 'prepare-sandbox':
        copy_config()
        for filename in ['windows_elevated_sandbox_setup.ps1','windows_sandbox_preflight.py']:
            copy_to(ROOT/'tools'/filename,'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+filename)
        print(json.dumps({'status':'PREPARED_NOT_RUN','guest_setup':'C:\\IntegrityLAB\\control\\preflight-labadmin\\windows_elevated_sandbox_setup.ps1',
            'transfer_digest_verified':True,'requires':'Manual administrator session in LAB guest','model_calls':0}))
        return
    if args.stage == 'metadata':
        acl = json.loads(require(powershell(lab_config.fill(CONTROL_ACL, quote=lab_config.ps_quote,
            WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname')))))
        copy_config()
        (ROOT/'evidence/WINDOWS-CONTROL-ACL.json').write_text(json.dumps(acl, indent=2)+'\n')
        for filename in ['windows_native_preflight.py', 'windows_sandbox_preflight.py', 'windows_cross_vm_preflight.py']:
            copy_to(ROOT/'tools'/filename, 'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+filename)
        require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe', [
            '-I', '-B', r'C:\IntegrityLAB\control\preflight-labadmin\windows_native_preflight.py',
            '--cli', binding['CLI_path'], '--sandbox-smoke',
            '--sandbox-implementation',args.sandbox_implementation], timeout=240))
        report = collect('native-preflight.json', 'WINDOWS-ELEVATED-NATIVE-PREFLIGHT.json' if args.sandbox_implementation=='elevated' else 'WINDOWS-NATIVE-PREFLIGHT.json')
    elif args.stage == 'sandbox':
        require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe', [
            '-I', '-B', r'C:\IntegrityLAB\control\preflight-labadmin\windows_sandbox_preflight.py',
            '--cli', binding['CLI_path'],'--implementation',args.sandbox_implementation], timeout=210))
        report = collect('sandbox-preflight.json', 'WINDOWS-SANDBOX-PREFLIGHT.json')
    elif args.stage == 'linux-readback':
        copy_config()
        copy_to(ROOT/'tools/windows_cross_vm_preflight.py', r'C:\IntegrityLAB\control\preflight-labadmin\windows_cross_vm_preflight.py')
        require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe', [
            '-I', '-B', r'C:\IntegrityLAB\control\preflight-labadmin\windows_cross_vm_preflight.py',
            '--readback-only'], timeout=60))
        report=collect('linux-readback.json','LINUX-FRESH-READBACK.json')
        import hashlib
        with (ROOT/'tools/linux_backend.py').open('rb') as stream:
            if report['backend']['backend_source_sha256'] != hashlib.file_digest(stream,'sha256').hexdigest():
                raise RuntimeError('Deployed Linux adapter source digest mismatch')
    else:
        # Management key is newly generated for this LAB; never transfer owner/production keys.
        acl = json.loads((ROOT/'evidence/WINDOWS-CONTROL-ACL.json').read_text())
        if acl['status'] != 'PASS':
            raise RuntimeError('Private guest control directory required before key transfer')
        copy_config()
        for filename in ['linux-management-key', 'linux-known-hosts']:
            copy_to(ROOT/'runtime/vms/control'/filename, 'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+filename)
        # Check effective key ACL without reading or returning any key bytes.
        require(powershell(r'''
$ErrorActionPreference='Stop'
$k=Get-Acl -LiteralPath C:\IntegrityLAB\control\preflight-labadmin\linux-management-key
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bad=@($k.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($me,'S-1-5-18','S-1-5-32-544') })
if($bad.Count){throw 'Unexpected key ACL principal'}
'LAB_KEY_ACL_PASS'
'''))
        require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe', [
            '-I', '-B', r'C:\IntegrityLAB\control\preflight-labadmin\windows_cross_vm_preflight.py'], timeout=150))
        report = collect('cross-vm.json', 'CROSS-VM-PREFLIGHT.json')
    print(json.dumps(report))
    if report['status'] not in {'PASS', 'PASS_METADATA_ONLY'}:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
