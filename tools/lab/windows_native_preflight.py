# SPDX-License-Identifier: BUSL-1.1
"""Guest-only native metadata and MXC shell checks. No chats, turns or models."""
from pathlib import Path
import argparse, json, os, queue, subprocess, threading, time
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT = Path('C:/IntegrityLAB')
ALLOWED = {'initialize', 'thread/loaded/list', 'config/read', 'hooks/list', 'account/read'}


def environment(home):
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(('CODEX_', 'INTEGRITY_', 'OPENAI_', 'ANTHROPIC_', 'AZURE_OPENAI'))}
    env['CODEX_HOME'] = str(home)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def hook_count(value):
    if isinstance(value, list):
        return sum(hook_count(x) for x in value)
    if isinstance(value, dict):
        return int(value.get('type') == 'command') + sum(hook_count(x) for x in value.values())
    return 0


class Metadata:
    def __init__(self, cli, home, cwd):
        self.errors = open(ROOT/'evidence'/('native-'+home.parent.name+'.log'), 'w')
        self.proc = subprocess.Popen([str(cli), 'app-server', '--listen', 'stdio://'], cwd=cwd,
            env=environment(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.errors, text=True, encoding='utf-8', errors='replace', bufsize=1)
        self.lines = queue.Queue()
        self.counter = 0
        def drain():
            for line in self.proc.stdout:
                self.lines.put(line)
            self.lines.put(None)
        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()

    def call(self, method, params):
        if method not in ALLOWED:
            raise PermissionError('Non-metadata RPC refused')
        self.counter += 1
        rid = self.counter
        self.proc.stdin.write(json.dumps({'jsonrpc':'2.0', 'id':rid, 'method':method, 'params':params})+'\n')
        self.proc.stdin.flush()
        deadline = time.monotonic()+45
        while time.monotonic() < deadline:
            line = self.lines.get(timeout=max(.01, deadline-time.monotonic()))
            if line is None:
                raise RuntimeError('Native metadata process exited')
            value = json.loads(line)
            if value.get('id') == rid:
                if 'error' in value:
                    raise RuntimeError('Metadata RPC failed: '+method)
                return value['result']
            if 'method' in value and 'id' in value:
                raise RuntimeError('Interactive callback refused')
        raise TimeoutError(method)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except (BrokenPipeError, subprocess.TimeoutExpired):
            self.proc.terminate()
            self.proc.wait(timeout=5)
        finally:
            self.reader.join(timeout=1)
            self.proc.stdout.close()
            self.errors.close()


def main():
    if os.name != 'nt' or os.environ.get('COMPUTERNAME') != lab_config.setting('vms.windows.hostname'):
        raise RuntimeError('Refusing to run outside the LAB Windows guest')
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--sandbox-smoke', action='store_true')
    parser.add_argument('--sandbox-implementation',choices=['mxc','elevated'],default='mxc')
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    if not cli.is_relative_to(Path('C:/Program Files/WindowsApps')) or cli.name != 'codex.exe':
        raise PermissionError('Expected the installed signed native package CLI')
    rows = []
    for actor in ('LAB-A', 'LAB-B'):
        home = ROOT/'clients'/actor/'.codex'
        cwd = ROOT/'workspaces'/actor
        cwd.mkdir(parents=True, exist_ok=True)
        home.mkdir(parents=True, exist_ok=True)
        if (home/'auth.json').exists():
            raise RuntimeError('Unexpected authentication in fresh profile')
        session = Metadata(cli, home, cwd)
        try:
            session.call('initialize', {'clientInfo':{'name':'lab-metadata-preflight','version':'1'},
                                       'capabilities':{'experimentalApi':True}})
            session.proc.stdin.write('{"jsonrpc":"2.0","method":"initialized","params":{}}\n')
            session.proc.stdin.flush()
            loaded = session.call('thread/loaded/list', {})
            ids = loaded.get('data', loaded.get('threadIds', []))
            if ids:
                raise RuntimeError('Fresh LAB profile has loaded chats')
            config = session.call('config/read', {'includeLayers':False, 'cwd':str(cwd)})
            config = config.get('config', config)
            hooks = session.call('hooks/list', {'cwds':[str(cwd)]})
            account = session.call('account/read', {'refreshToken':False})
            if account.get('account') or hook_count(hooks):
                raise RuntimeError('Unexpected authentication or hooks in the clean guest profile')
            # Retain only safe metadata; never account values or credentials.
            rows.append({'actor':actor, 'initialize':'PASS', 'loaded_threads':0,
                'mcp_names':sorted((config.get('mcp_servers') or {}).keys()),
                'hook_commands':hook_count(hooks), 'hooks_result_keys':sorted(hooks), 'account_present':False,
                'threads_created':0, 'model_turns_started':0})
        finally:
            session.close()
        if args.sandbox_smoke:
            rows[-1]['sandbox_implementation'] = args.sandbox_implementation
            try:
                result = subprocess.run([str(cli), '-c', 'windows.sandbox='+args.sandbox_implementation, 'sandbox',
                    '--include-managed-config', '--permission-profile', ':workspace', '--',
                    'cmd.exe', '/d', '/c', 'echo SANDBOX_OK'], cwd=cwd, env=environment(home),
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
                rows[-1]['sandbox_startup'] = 'PASS' if result.returncode == 0 and result.stdout.strip() == 'SANDBOX_OK' else 'FAIL'
                rows[-1]['sandbox_exit_code'] = result.returncode
                if rows[-1]['sandbox_startup'] != 'PASS':
                    rows[-1]['sandbox_reason'] = result.stderr[-600:]
            except subprocess.TimeoutExpired:
                rows[-1].update(sandbox_startup='FAIL', sandbox_exit_code=None,
                                sandbox_reason='STARTUP_TIMEOUT_60_SECONDS')
            if rows[-1]['sandbox_startup'] != 'PASS':
                break  # Preserve the first failure; do not repeat the same failed launch for another actor.
    report = {'schema':'integrity-lab.windows-native-preflight.v1', 'actors':rows,
        'status':'FAIL' if any(r.get('sandbox_startup')=='FAIL' for r in rows) else 'PASS_METADATA_ONLY',
        'agents':'NOT_RUN', 'models':'NOT_RUN', 'benchmarks':'NOT_RUN',
        'Desktop_owner_binding':'NOT_RUN', 'peer_delivery':'NOT_RUN',
        'strict_role_sandbox':'NOT_RUN', 'intent_admissions':0}
    (ROOT/'evidence/native-preflight.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
