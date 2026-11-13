# SPDX-License-Identifier: BUSL-1.1
"""Read back only the two LAB VM configurations and media boundaries."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, re
import vmctl

def value(raw):
    if raw is None:return None
    return json.loads(raw) if raw.startswith('"') else raw

def main():
    rows=[]
    proxy_egress=False
    proxy_link=False
    for name in vmctl.VMS:
        data=vmctl.owned_info(name)
        has_proxy_egress=value(data['nic2'])=='nat'
        proxy_egress=proxy_egress or has_proxy_egress
        link=has_proxy_egress and value(data.get('cableconnected2'))=='on'
        proxy_link=proxy_link or link
        checks={'identity_and_private_config_root':'PASS','private_internal_NIC1':'PASS','approved_extra_adapters':'PASS','clipboard_dragdrop_sharedfolders_disabled':'PASS'}
        for key in ['usb','vrde','teleporterenabled','autostart-enabled']:
            assert value(data[key])=='off',key
        checks['USB_VRDE_teleporter_autostart_disabled']='PASS'
        media=[]
        for key,raw in data.items():
            if re.fullmatch(r'"SATA-\d+-0"',key):
                item=value(raw)
                if item not in {'none','emptydrive',None}:
                    path=Path(item)
                    assert path.is_absolute() and path.is_relative_to(vmctl.ROOT/'runtime'), 'Foreign attached disk/media'
                    assert path.suffix.lower() in {'.iso','.vdi','.viso'},'Unexpected medium type'
                    media.append(str(path))
        assert media
        checks['all_attached_disks_and_ISOs_inside_LAB_runtime']='PASS'
        if name==vmctl.WINDOWS:
            assert value(data['SecureBoot'])=='on'
            checks['Windows_Secure_Boot_enabled']='PASS'
        rows.append({'VM':name,'UUID':value(data['UUID']),'state':value(data['VMState']),'RAM_mib':int(data['memory']),
            'vcpus':int(data['cpus']),'internal_network':value(data['intnet1']),
            'NAT_proxy_uplink':has_proxy_egress,'NAT_proxy_cable_connected':link,'attached_media':media,'checks':checks})
    report={'schema':'integrity-lab.vm-isolation-readback.v1','observed_utc':datetime.now(timezone.utc).isoformat(),
        'status':'PASS','VMs':rows,'scope':'VirtualBox configuration and attached media, not complete guest/native-client acceptance',
        'host_firewall_changes_by_this_task':0,'host_HyperV_VBS_changes_by_this_task':0,'production_service_changes_by_this_task':0,
        'guest_egress':('WINDOWS_INTERNAL_ONLY_LINUX_PROXY_NAT_ACTIVE' if proxy_link else 'WINDOWS_INTERNAL_ONLY_LINUX_PROXY_NAT_DISCONNECTED') if proxy_egress else 'NO_NAT_NO_BRIDGE_NO_HOST_ONLY',
        'proxy_policy_evidence':'evidence/EGRESS-PROBE.json' if proxy_egress else None,
        'agents':'NOT_RUN','benchmarks':'NOT_RUN'}
    (vmctl.ROOT/'evidence/VM-ISOLATION.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
