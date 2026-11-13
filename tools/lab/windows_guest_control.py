# SPDX-License-Identifier: BUSL-1.1
"""Bounded control of the named LAB guest through Oracle Guest Additions.

No model/agent launcher. Credentials remain in the existing private password file.
"""
from pathlib import Path
import base64
import hashlib
import json
import subprocess

from vmctl import ROOT, UUIDS, VBOX, WINDOWS, owned_info
import lab_config

UUID = UUIDS[WINDOWS]
PASSWORD = ROOT / 'runtime/vms/control/windows-labadmin-password'
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


def ready():
    info = owned_info(WINDOWS)
    if json.loads(info['VMState']) != 'running':
        raise RuntimeError('LAB Windows must be running')


def run(executable, arguments, timeout=120):
    ready()
    if executable not in {POWERSHELL, r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe'}:
        raise PermissionError('Unexpected guest runtime')
    return subprocess.run([str(VBOX), 'guestcontrol', UUID, 'run', '--exe', executable,
        '--username', 'labadmin', '--passwordfile', str(PASSWORD),
        '--timeout', str(timeout*1000), '--wait-stdout', '--wait-stderr', '--',
        *arguments], capture_output=True, text=True,
        encoding='utf-8', errors='replace', timeout=timeout+15)


def powershell(source, timeout=120):
    # This is a guest transport encoding, not shell interpolation or a credential.
    encoded = base64.b64encode(source.encode('utf-16-le')).decode('ascii')
    return run(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive',
                           '-EncodedCommand', encoded], timeout)


def copy_to(source, destination):
    ready()
    source = Path(source).resolve(strict=True)
    allowed = {ROOT/'tools'/name for name in (
        'windows_native_preflight.py', 'windows_cross_vm_preflight.py',
        'windows_sandbox_preflight.py', 'windows_elevated_sandbox_setup.ps1',
        'windows_native_binding.py', 'linux_mcp_sandbox_setup.py','linux_backend.py',
        'windows_account_isolation.py','windows_egress_setup.py','lab_egress_proxy.py',
        'windows_account_proxy.ps1','windows_native_compat_stage.py','windows_native_hook_stage.py',
        'windows_hook_review_handoff.ps1','windows_native_canary.py','windows_efficiency_smoke.py',
        'lab_config.py')}
    # Guest-side tools read the same lab configuration next to themselves.
    allowed.add(lab_config.location().resolve())
    allowed.add(ROOT/'controller/native-compatibility-candidate/delegation-native-reader.py')
    allowed.add(ROOT/'controller/native-envelope-candidate/integrity_client_turn_envelope.py')
    allowed.add(ROOT/'controller/native-envelope-candidate-v3/integrity_client_turn_envelope.py')
    allowed.add(ROOT/'runtime/diagnostics/efficiency-smoke-input.json')
    allowed.add(ROOT/'runtime/diagnostics/efficiency-files-input.json')
    allowed |= {ROOT/'runtime/vms/control'/name for name in (
        'linux-management-key', 'linux-known-hosts')}
    if source not in allowed or destination != 'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+source.name:
        raise PermissionError('Only explicitly prepared LAB preflight inputs may be transferred')
    p = subprocess.run([str(VBOX), 'guestcontrol', UUID, 'copyto', '--username', 'labadmin',
        '--passwordfile', str(PASSWORD), str(source), destination],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    if p.returncode:
        raise RuntimeError('Guest file transfer failed: '+p.stderr[-400:])
    actual = powershell("(Get-FileHash -LiteralPath '"+destination+"' -Algorithm SHA256).Hash", timeout=45)
    with source.open('rb') as stream:
        expected = hashlib.file_digest(stream, 'sha256').hexdigest()
    # Digest comparison stays internal, including for the freshly generated LAB key.
    if actual.returncode or actual.stdout.strip().lower() != expected:
        raise RuntimeError('Guest transfer digest mismatch')


def copy_config():
    """Give guest-side tools the lab configuration module and file next to themselves."""
    for source in (ROOT/'tools/lab_config.py', lab_config.location()):
        copy_to(source, 'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+Path(source).name)


READBACK = r'''
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne @WINDOWS_HOSTNAME@){throw 'Wrong guest'}
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Oracle|innotek'){throw 'Wrong hypervisor'}
$s=Get-ItemProperty -LiteralPath HKLM:\SYSTEM\Setup
$w=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$p=Get-AppxPackage -Name OpenAI.Codex
$service=Get-Service -Name VBoxService -ErrorAction SilentlyContinue
$result=[ordered]@{
 schema='integrity-lab.windows-independent-readback.v1';hostname=$env:COMPUTERNAME;
 setup_in_progress=[int]$s.SystemSetupInProgress;oobe_in_progress=[int]$s.OOBEInProgress;
 installer_autologon_disabled=($w.AutoAdminLogon -eq '0');
 cached_installer_password_absent=($w.PSObject.Properties.Name -notcontains 'DefaultPassword');
 guest_additions_service_present=($null -ne $service);
 guest_additions_service_running=($null -ne $service -and $service.Status -eq 'Running');
 native_package_version=[string]$p.Version;
 CLI_path=(Join-Path $p.InstallLocation 'app\resources\codex.exe');
 ssh_client_present=(Test-Path -LiteralPath C:\Windows\System32\OpenSSH\ssh.exe);
 model_calls=0;agents='NOT_RUN';benchmarks='NOT_RUN'
}
$result | ConvertTo-Json -Compress
'''


if __name__ == '__main__':
    result = powershell(lab_config.fill(READBACK, quote=lab_config.ps_quote,
        WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname')), timeout=45)
    if result.returncode:
        raise SystemExit(result.stderr[-700:])
    report = json.loads(result.stdout.lstrip('\ufeff'))
    required = (report['setup_in_progress'] == 0, report['oobe_in_progress'] == 0,
        report['installer_autologon_disabled'], report['cached_installer_password_absent'],
        report['guest_additions_service_running'], report['ssh_client_present'])
    report['status'] = 'PASS' if all(required) else 'FAIL'
    (ROOT/'evidence/WINDOWS-INDEPENDENT-READBACK.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)
