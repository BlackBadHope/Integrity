# SPDX-License-Identifier: BUSL-1.1
"""Read bounded Setup diagnostics from the stopped LAB guest, without mounting it."""
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import json, re, sys, xml.etree.ElementTree as ET

from dissect.hypervisor.disk.vdi import VDI
from dissect.volume.disk import Disk
from dissect.ntfs import NTFS
from dissect.regf import RegistryHive

sys.path.insert(0, str(Path(__file__).absolute().parent))
from vmctl import ROOT, WINDOWS, owned_info


def main():
    info = owned_info(WINDOWS)
    if json.loads(info['VMState']) not in {'saved', 'poweroff'}:
        raise RuntimeError('Freeze the guest before read-only filesystem diagnostics')
    config = Path(json.loads(info['CfgFile']))
    current = next(json.loads(v) for k, v in info.items() if k.strip('"') == 'SATA-0-0')
    current = Path(current).resolve()
    tree = ET.parse(config)
    chains = {}

    def walk(node, chain):
        if node.tag.endswith('HardDisk'):
            path = (config.parent / node.attrib['location']).resolve()
            if not path.is_relative_to(ROOT / 'runtime/vms') or path.suffix.lower() != '.vdi':
                raise PermissionError('Foreign disk refused')
            chain = [*chain, path]
            chains[path] = chain
        for child in node:
            walk(child, chain)

    walk(tree.getroot(), [])
    chain = chains[current]
    before = [(p.stat().st_size, p.stat().st_mtime_ns) for p in chain]
    report = {'schema': 'integrity-lab.windows-disk-readonly.v1',
              'observed_utc': datetime.now(timezone.utc).isoformat(),
              'VM_state': json.loads(info['VMState']), 'disk_layers': len(chain),
              'read_only': True, 'mounted': False, 'logs': [], 'agents': 'NOT_RUN'}
    with ExitStack() as stack:
        parent = None
        for path in chain:
            vdi = stack.enter_context(VDI(path, parent=parent))
            parent = vdi.open()
        disk = Disk(parent)
        windows = max(disk.partitions, key=lambda p: p.size)
        ntfs = NTFS(windows.open())
        system = RegistryHive(ntfs.mft.get('Windows/System32/config/SYSTEM').open())
        report['setup_registry'] = {'hive_in_transaction': system.in_transaction}
        for key, name in [('Setup', n) for n in ('SystemSetupInProgress', 'OOBEInProgress', 'SetupPhase', 'SetupType', 'RestartSetup')]+[('Setup/Status/ChildCompletion', 'setup.exe')]:
            try:
                value = system.open(key.replace('/', '\\')).value(name).value
                if not isinstance(value, int):
                    raise ValueError('Numeric Setup state expected')
                report['setup_registry'][key+'/'+name] = value
            except Exception as e:
                report['setup_registry'][key+'/'+name] = type(e).__name__
        for name in ['Windows/Panther/setupact.log', 'Windows/Panther/setuperr.log',
                     'Windows/Panther/UnattendGC/setupact.log', 'Windows/Panther/UnattendGC/setuperr.log',
                     'Windows/INF/setupapi.dev.log', 'IntegrityLAB/evidence/runtime.json']:
            row = {'path': name}
            try:
                record = ntfs.mft.get(name)
                stream = record.open()
                size = record.size()
                stream.seek(max(0, size - 65536))
                data = stream.read(min(size, 65536))
                text = data.decode('utf-16-le' if b'\x00' in data[:100] else 'utf-8', errors='replace')
                # Persist only fixed-shape timestamps, routine names and numeric codes.
                # Never export raw Setup/unattend content or cached credentials.
                events = []
                for line in text.splitlines():
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.:\d ]*\s+(Info|Error|Warning)\s+(?:\[0x[0-9a-fA-F]+\]\s+)?([A-Z0-9]+)\s+([A-Za-z0-9_:.-]+)', line)
                    if match:
                        events.append({'time': match[1], 'level': match[2], 'component': match[3],
                                       'routine': match[4], 'codes': re.findall(r'0x[0-9a-fA-F]{4,16}', line)[:3]})
                row.update(present=True, bytes=size, last_events=events[-16:])
                if 'setuperr.log' in name:
                    safe = []
                    confirmed_values = []
                    for line in text.splitlines():
                        for candidate in re.findall(r'\b[0-9A-Fa-f]{24,}\b', line):
                            try:
                                decoded = bytes.fromhex(candidate).decode('utf-16-le').strip('\x00')
                                if decoded in {'Public','Home','Work','Other'}:
                                    confirmed_values.append(decoded)
                            except (ValueError, UnicodeError):
                                pass
                        if re.search(r'password|credential|token|cookie|product.?key|<|>', line, re.I):
                            continue
                        if 'Error' in line:
                            safe.append(re.sub(r'[A-Za-z0-9_+/=-]{24,}', '[opaque-redacted]', line)[:500])
                    row['safe_error_summary'] = safe[-12:]
                    row['confirmed_network_enum_values'] = confirmed_values
                if name == 'Windows/Panther/UnattendGC/setupact.log':
                    row['network_location_diagnostic'] = [line[:500] for line in text.splitlines()
                        if 'NetworkLocation' in line and not re.search(r'password|credential|token|cookie|<|>', line, re.I)][-8:]
                if name.endswith('.dev.log'):
                    row['last_section_times'] = re.findall(r'\b(?:Section start|Section end) (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', text)[-6:]
            except Exception as e:
                row.update(present=False, error=type(e).__name__)
            report['logs'].append(row)
    after = [(p.stat().st_size, p.stat().st_mtime_ns) for p in chain]
    report['disk_metadata_unchanged'] = before == after
    if before != after:
        raise RuntimeError('Disk changed during the bounded read')
    (ROOT / 'evidence/WINDOWS-DISK-READONLY.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
