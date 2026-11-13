# SPDX-License-Identifier: BUSL-1.1
"""Prepare only the owned Windows guest for an offline, unactivated install."""
from pathlib import Path
import argparse, hashlib, io, json, re, secrets, shutil, subprocess
import pycdlib
import vmctl
import lab_config

ROOT=vmctl.ROOT
NAME=vmctl.WINDOWS
UUID=vmctl.UUIDS[NAME]
MEDIA=ROOT/'runtime/media/windows-11-26H2'
ISO=MEDIA/'Windows11_Client_x64_en-gb_26300_9457.iso'
CONTROL=vmctl.BASE/'control'
def main(refresh=False,attempt=None):
    raw=vmctl.owned_info(NAME)
    assert json.loads(raw['VMState'])=='poweroff'
    if attempt and (not re.fullmatch(r'[a-z0-9-]{1,32}',attempt) or refresh):
        raise ValueError('A fresh safe attempt name is required; refresh is separate')
    receipt=ROOT/'evidence'/('WINDOWS-UNATTENDED-PREPARED'+('-'+attempt if attempt else '')+'.json')
    if receipt.exists() and not refresh:raise FileExistsError('Unattended preparation exists; inspect actual state before repeating')
    if refresh:
        old=json.loads(receipt.read_text())
        assert old['status']=='PREPARED_NOT_BOOTED' and old['UUID']==UUID
    expected=json.loads((ROOT/'evidence/WINDOWS-IMAGE-VERIFICATION.json').read_text())
    assert str(ISO)==expected['Image'] and ISO.stat().st_size==expected['Bytes']
    from integrity_guardian._windows_files import create_private_directory_tree
    create_private_directory_tree(CONTROL)
    target=CONTROL/('windows-install-'+attempt) if attempt else MEDIA
    if attempt:
        if target.exists():raise FileExistsError('Attempt exists; inspect actual VM state instead of repeating')
        create_private_directory_tree(target)
    password=CONTROL/'windows-labadmin-password'
    if not password.exists():
        with password.open('x',encoding='ascii') as f:f.write(secrets.token_urlsafe(32)+'aA9!')
    template=Path(lab_config.setting('host.unattended_template'))
    text=template.read_text(encoding='utf-8')
    # This VM satisfies Windows requirements. Do not install Oracle's default
    # LabConfig bypass commands into either Windows PE or the guest OS.
    text=re.sub(r'<RunAsynchronous>.*?</RunAsynchronous>','',text,flags=re.S)
    text=re.sub(r'<ProductKey>.*?</ProductKey>','<ProductKey><WillShowUI>Never</WillShowUI></ProductKey>',text,flags=re.S)
    # Microsoft unattended schema accepts Home/Work/Other, not the UI label Public.
    text=text.replace('<NetworkLocation>Home</NetworkLocation>','<NetworkLocation>Other</NetworkLocation>')
    text=text.replace('<ProtectYourPC>3</ProtectYourPC>','<ProtectYourPC>1</ProtectYourPC>')
    text=text.replace('<HideEULAPage>true</HideEULAPage>','<HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>')
    assert '<RunAsynchronous>' not in text and '<Key>@@VBOX_INSERT_PRODUCT_KEY' not in text and 'reg.exe ADD HKLM' not in text
    custom=target/'lab-unattended-template.xml';custom.write_text(text,encoding='utf-8')
    payload=ROOT/'runtime/media/windows-runtime-v1.iso'
    runtime_receipt=json.loads((ROOT/'evidence/WINDOWS-RUNTIME-MEDIA.json').read_text())
    assert payload.is_file() and payload.stat().st_size==runtime_receipt['bytes']
    post=target/'lab-postinstall-template.cmd'
    post.write_text('@echo off\r\n'
        'for %%D in (D E F G H I) do if exist "%%D:\\vboxadditions\\VBoxWindowsAdditions.exe" start /wait "" "%%D:\\vboxadditions\\VBoxWindowsAdditions.exe" /S\r\n'
        'for %%D in (D E F G H I) do if exist "%%D:\\WINPF.PS1" powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%%D:\\WINPF.PS1"\r\n',encoding='ascii')
    config=Path(json.loads(raw['CfgFile']))
    if not refresh:
        shutil.copy2(config,(target if attempt else CONTROL)/'windows-before-unattended.vbox')
        vmctl.call(['modifyvm',UUID,'--cpus','3','--uart1','0x3f8','4','--uart-mode1','file',ROOT/'evidence'/('windows-serial-'+attempt+'.log' if attempt else 'windows-serial.log')])
    if not refresh and not attempt:
        vmctl.call(['modifynvram',UUID,'inituefivarstore'])
        vmctl.call(['modifynvram',UUID,'enrollmssignatures'])
        vmctl.call(['modifynvram',UUID,'enrollorclpk'])
        vmctl.call(['modifynvram',UUID,'secureboot','--enable'])
    args=['unattended','install',UUID,'--iso='+str(ISO),'--user=labadmin','--user-password-file='+str(password),
        '--admin-password-file='+str(password),'--full-user-name=Integrity LAB Administrator','--hostname='+lab_config.setting('vms.windows.hostname').lower()+'.lab.invalid',
        '--image-index=6','--locale=en_GB','--language=en-GB','--country='+lab_config.setting('vms.windows.country'),'--time-zone=UTC',
        '--install-additions','--additions-iso='+lab_config.setting('host.guest_additions_iso'),'--no-install-txs',
        '--script-template='+str(custom),'--post-install-template='+str(post),'--start-vm=none']
    if attempt:
        fresh_disk=vmctl.BASE/NAME/('Windows-'+attempt+'.vdi')
        if fresh_disk.exists():raise FileExistsError('Fresh attempt disk already exists')
        if shutil.disk_usage(ROOT).free < 40*(1024**3):raise RuntimeError('Need 40 GiB free before another install attempt')
        vmctl.call(['createmedium','disk','--filename',fresh_disk,'--size','65536','--format','VDI','--variant','Standard'])
        vmctl.call(['storageattach',UUID,'--storagectl','SATA','--port','0','--device','0','--type','hdd','--medium',fresh_disk])
        args+=['--auxiliary-base-path='+str(target/'Unattended-')]
    result=subprocess.run([str(vmctl.VBOX),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    # VBox output may include installation credentials. Never log that output.
    if result.returncode:raise RuntimeError('VBox unattended preparation failed (output withheld because it may contain credentials); inspect VM state before retry')
    vmctl.call(['storageattach',UUID,'--storagectl','SATA','--port','3','--device','0','--type','dvddrive','--medium',payload])
    # An empty disk falls through to DVD. After Setup's first reboot the newly
    # installed bootloader must take precedence over the no-prompt install ISO.
    vmctl.call(['modifyvm',UUID,'--boot1','disk','--boot2','dvd'])
    row={'schema':'integrity-lab.windows-unattended.v1','VM':NAME,'UUID':UUID,'status':'PREPARED_NOT_BOOTED',
        'image_index':6,'edition':'Windows 11 Pro','activation':'NO_KEY_NOT_REQUESTED','secure_boot':'ENABLED_GUEST_ONLY',
        'TPM':'VIRTUAL_2.0','vcpus':3,'attempt':attempt,'credentials':'FRESH_LAB_ONLY_PRIVATE_VM_CONTROL_DIRECTORY',
        'source_template_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),
        'custom_template_sha256':hashlib.sha256(custom.read_bytes()).hexdigest(),
        'postinstall_sha256':hashlib.sha256(post.read_bytes()).hexdigest(),
        'guest_runtime_iso_sha256':runtime_receipt['sha256'],
        'setup_requirement_bypasses':False,'test_execution_service':False,'agents':'NOT_RUN','benchmarks':'NOT_RUN'}
    receipt.write_text(json.dumps(row,indent=2)+'\n')
    print(json.dumps(row))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--refresh-postinstall',action='store_true');parser.add_argument('--attempt');args=parser.parse_args()
    main(refresh=args.refresh_postinstall,attempt=args.attempt)
