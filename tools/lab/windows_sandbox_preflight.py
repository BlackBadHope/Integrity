# SPDX-License-Identifier: BUSL-1.1
"""Guest-only role sandbox probes using synthetic files, with zero model calls."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import socket
import subprocess
import threading
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT = Path('C:/IntegrityLAB')


def guest_guard():
    if os.name != 'nt' or os.environ.get('COMPUTERNAME') != lab_config.setting('vms.windows.hostname'):
        raise RuntimeError('LAB Windows guest required')


def probe(actor, port):
    rows = []
    own = ROOT/'workspaces'/actor
    foreign = ROOT/'workspaces'/('LAB-B' if actor == 'LAB-A' else 'LAB-A')

    def check(name, fn):
        try:
            fn()
            rows.append({'claim': name, 'status': 'PASS'})
        except Exception as e:
            rows.append({'claim': name, 'status': 'FAIL', 'reason': type(e).__name__+': '+str(e)[:180]})

    def denied(path):
        try:
            with path.open('rb'):
                pass  # Even an isolation failure never reads bytes from the foreign file.
        except PermissionError:
            return
        except FileNotFoundError:
            raise AssertionError('Missing file is not proof of isolation')
        raise AssertionError('Foreign file was openable')

    def network_denied():
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=2):
                pass
        except PermissionError:
            return
        except OSError as e:
            if getattr(e, 'winerror', None) in {10013, 10051, 10065}:
                return
            raise AssertionError('No explicit policy denial: '+str(getattr(e, 'winerror', None)))
        raise AssertionError('Guest loopback sentinel reachable')

    check('own_input_readable', lambda: (own/'input.txt').read_text())
    check('own_output_writable', lambda: (own/'output.txt').write_text('Synthetic preflight only.\n'))
    check('foreign_participant_denied', lambda: denied(foreign/'input.txt'))
    check('controller_oracle_denied', lambda: denied(ROOT/'controller/oracle.txt'))
    check('guest_owner_private_sentinel_denied', lambda: denied(ROOT/'control/preflight-labadmin/private-sentinel.txt'))
    native_config=own/'.codex/hooks.json'
    def native_read_only():
        assert native_config.is_file(), 'Expected prepared Native hook config'
        try:
            with native_config.open('ab'):pass
        except PermissionError:return
        raise AssertionError('Native hook config openable for write')
    check('native_hook_config_read_only',native_read_only)
    check('guest_loopback_denied', network_denied)
    report = {'actor': actor, 'checks': rows, 'Python_audit_guard': False,
              'status': 'PASS' if all(r['status'] == 'PASS' for r in rows) else 'FAIL'}
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


def main():
    guest_guard()
    p = argparse.ArgumentParser()
    p.add_argument('--cli', type=Path)
    p.add_argument('--implementation',choices=['mxc','elevated'],default='mxc')
    p.add_argument('--probe-actor', choices=['LAB-A', 'LAB-B'])
    p.add_argument('--sentinel-port', type=int)
    args = p.parse_args()
    if args.probe_actor:
        return probe(args.probe_actor, args.sentinel_port)
    cli = args.cli.resolve(strict=True)
    if not cli.is_relative_to(Path('C:/Program Files/WindowsApps')) or cli.name != 'codex.exe':
        raise PermissionError('Expected signed native package CLI')
    (ROOT/'controller').mkdir(exist_ok=True)
    (ROOT/'controller/oracle.txt').write_text('Synthetic controller-only oracle.\n')
    (ROOT/'control/preflight-labadmin/private-sentinel.txt').write_text('Synthetic guest management boundary.\n')
    for actor in ['LAB-A', 'LAB-B']:
        own = ROOT/'workspaces'/actor
        own.mkdir(parents=True, exist_ok=True)
        (own/'input.txt').write_text('Synthetic '+actor+' input.\n')
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen()
    port = server.getsockname()[1]
    def drain():
        while True:
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                return
    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    with socket.create_connection(('127.0.0.1', port), timeout=2):
        pass
    rows = []
    try:
        for actor in ['LAB-A', 'LAB-B']:
            home = ROOT/'clients'/actor/'.codex'
            if (home/'auth.json').exists():
                raise PermissionError('Fresh unauthenticated profile required')
            config = home/'config.toml'
            old = config.read_bytes()
            digest = hashlib.sha256(old).hexdigest()
            backup = home/('config.before-role-preflight.'+digest[:12]+'.toml')
            if not backup.exists():
                backup.write_bytes(old)
            text = '''approval_policy = "never"
default_permissions = "lab-role"
web_search = "disabled"
[windows]
sandbox = "mxc"
[features]
prefer_mxc = true
apps = false
plugins = false
memories = false
[agents]
enabled = false
[memories]
use_memories = false
generate_memories = false
[apps._default]
enabled = false
destructive_enabled = false
open_world_enabled = false
[plugins."codex-app-tools@openai-bundled"]
enabled = false
[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app]
enabled = false
enabled_tools = []
[mcp_servers.codex_app]
enabled = false
command = ""
enabled_tools = []
[permissions.lab-role.filesystem]
":root" = "deny"
":minimal" = "read"
'''
            paths = {ROOT/'runtime/Python': 'read', ROOT/'runtime/venv': 'read',
                     Path(__file__).resolve(): 'read', ROOT/'workspaces'/actor: 'write'}
            if (ROOT/'workspaces'/actor/'.codex').is_dir():
                paths[ROOT/'workspaces'/actor/'.codex']='read'
            for path, access in paths.items():
                text += "'"+str(path)+"' = \""+access+'"\n'
            text += '[permissions.lab-role.network]\nenabled = false\n'
            text=text.replace('sandbox = "mxc"','sandbox = "'+args.implementation+'"')
            if args.implementation=='elevated':
                text=text.replace('prefer_mxc = true','prefer_mxc = false')
            config.write_text(text, encoding='utf-8')
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith(
                ('CODEX_', 'INTEGRITY_', 'OPENAI_', 'ANTHROPIC_', 'AZURE_OPENAI'))}
            env['CODEX_HOME'] = str(home)
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            try:
                result = subprocess.run([str(cli), '-c', 'windows.sandbox='+args.implementation, 'sandbox',
                    '--include-managed-config', '--permission-profile', 'lab-role', '--',
                    str(ROOT/'runtime/venv/Scripts/python.exe'), '-I', '-B', str(Path(__file__).resolve()),
                    '--probe-actor', actor, '--sentinel-port', str(port)], cwd=ROOT/'workspaces'/actor,
                    env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
            except subprocess.TimeoutExpired:
                rows.append({'actor':actor, 'status':'FAIL_STARTUP', 'exit_code':None,
                             'reason':'STARTUP_TIMEOUT_90_SECONDS', 'config_preimage_sha256':digest})
                break
            try:
                row = json.loads(result.stdout.strip())
            except ValueError:
                row = {'actor': actor, 'status': 'FAIL_STARTUP', 'stderr': result.stderr[-1000:]}
            row['exit_code'] = result.returncode
            row['config_preimage_sha256'] = digest
            rows.append(row)
    finally:
        server.close()
        thread.join(timeout=.2)
    report = {'schema': 'integrity-lab.windows-role-sandbox.v1', 'actors': rows,
        'status': 'PASS' if all(x['status'] == 'PASS' and x['exit_code'] == 0 for x in rows) else 'FAIL',
        'sandbox_implementation':args.implementation,
        'sentinel_baseline': 'REACHABLE_BEFORE_SANDBOX', 'agents': 'NOT_RUN', 'models': 'NOT_RUN',
        'benchmarks': 'NOT_RUN', 'scope': 'Guest shell role filesystem and network only; not MCP or Desktop ownership'}
    (ROOT/'evidence/sandbox-preflight.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
