# SPDX-License-Identifier: BUSL-1.1
"""Create new guest-only NoCloud media from pinned offline wheels."""
from pathlib import Path
import hashlib, io, json, sys
import pycdlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import vmctl
import lab_config

ROOT=vmctl.ROOT
MEDIA=ROOT/'runtime/media'
OUT=MEDIA/'linux-seed-v4.iso'
def main():
    d=vmctl.info(vmctl.LINUX)
    assert json.loads(d['UUID'])==vmctl.UUIDS[vmctl.LINUX]
    hostname=lab_config.setting('vms.linux.hostname');home=lab_config.setting('linux_guest.home')
    address=lab_config.setting('network.linux_guest_ip')+'/'+str(lab_config.setting('network.prefix_length'))
    assert Path(json.loads(d['CfgFile'])).is_relative_to(vmctl.BASE)
    assert json.loads(d['VMState'])=='poweroff'
    if OUT.exists():raise FileExistsError('Seed exists; review actual state before replacement')
    from integrity_guardian._windows_files import create_private_directory_tree
    control=vmctl.BASE/'control'
    create_private_directory_tree(control)
    keyfile=control/'linux-management-key'
    if not keyfile.exists():
        key=ed25519.Ed25519PrivateKey.generate()
        with keyfile.open('xb') as f:f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()))
        (control/'linux-management-key.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH))
    pub=(control/'linux-management-key.pub').read_text().strip()
    mac=json.loads(d['macaddress1']);mac=':'.join(mac[i:i+2] for i in range(0,12,2)).lower()
    user='''#cloud-config
hostname: '''+hostname+'''
manage_etc_hosts: true
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false
users:
  - name: lab
    gecos: Integrity LAB administrator
    homedir: '''+home+'''
    shell: /bin/bash
    lock_passwd: true
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - '''+pub+'''
runcmd:
  - [chmod, '0700', '''+home+''']
  - [mkdir, -p, /mnt/labseed]
  - [mount, -o, ro, -L, CIDATA, /mnt/labseed]
  - [/bin/bash, /mnt/labseed/bootstrap.sh]
'''
    network='''version: 2
ethernets:
  lab0:
    match:
      macaddress: "'''+mac+'''"
    set-name: lab0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    link-local: []
    addresses: ['''+address+''']
'''
    script='''#!/bin/bash
set -euo pipefail
umask 077
exec > >(tee /var/log/integrity-lab-bootstrap.log) 2>&1
trap 'rc=$?; echo INTEGRITY_LAB_BOOTSTRAP_EXIT=$rc; sync; /sbin/shutdown -h now' EXIT
echo INTEGRITY_LAB_BOOTSTRAP_BEGIN
mkdir -p /opt/integrity-lab/tools
cp /mnt/labseed/tools/*.py /mnt/labseed/tools/lab.json /opt/integrity-lab/tools/
chmod -R go-w /opt/integrity-lab
python3 -m venv --without-pip /opt/integrity-lab/venv
PYTHONPATH=$(find /mnt/labseed/wheels -name 'pip-*.whl' -print -quit) /opt/integrity-lab/venv/bin/python -m pip install --quiet --no-index --find-links=/mnt/labseed/wheels pip integrity-guardian==6.1.1 integrity-action-log==2.10.0 integrity-client-memory==1.9.0
chmod -R a+rX,go-w /opt/integrity-lab
chmod 0700 '''+home+'''
runuser -u lab -- env HOME='''+home+''' /opt/integrity-lab/venv/bin/python /opt/integrity-lab/tools/linux_guest_preflight.py
'''
    files={'user-data':user.encode(),'meta-data':('instance-id: '+hostname+'-v4\nlocal-hostname: '+hostname+'\n').encode(),
        'network-config':network.encode(),'bootstrap.sh':script.encode()}
    for name in ['linux_backend.py','linux_guest_preflight.py','lab_config.py']:
        files['tools/'+name]=(ROOT/'tools'/name).read_bytes()
    # Guest-side tools read the same lab configuration next to themselves.
    files['tools/lab.json']=lab_config.location().read_bytes()
    for p in sorted((MEDIA/'linux-payload/wheels').glob('*.whl')):files['wheels/'+p.name]=p.read_bytes()
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='CIDATA')
    for name in ['tools','wheels']:iso.add_directory(iso_path='/'+name.upper(),rr_name=name,joliet_path='/'+name)
    for i,(name,data) in enumerate(files.items()):
        parent,_,leaf=name.rpartition('/')
        joliet_leaf=leaf if len(leaf)<=64 else 'F%06d.DAT'%i
        iso.add_fp(io.BytesIO(data),len(data),iso_path=('/'+parent.upper() if parent else '')+'/F%06d.DAT;1'%i,
            rr_name=leaf,joliet_path=('/'+parent if parent else '')+'/'+joliet_leaf)
    iso.write(str(OUT));iso.close()
    report={'schema':'integrity-lab.seed-media.v1','image':str(OUT),'sha256':hashlib.sha256(OUT.read_bytes()).hexdigest(),
        'members':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()},'contains_private_key':False,
        'contains_production_data':False,'agents':'NOT_RUN','benchmarks':'NOT_RUN'}
    (ROOT/'evidence/LINUX-SEED-MANIFEST.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'image':str(OUT),'bytes':OUT.stat().st_size,'members':len(files),'sha256':report['sha256']}))
if __name__=='__main__':main()
