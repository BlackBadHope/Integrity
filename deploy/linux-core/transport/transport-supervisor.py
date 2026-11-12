"""Linux-only bounded stdio supervisor; no MCP/admission payload interpretation.

The verified child owns Guardian initialization. This proxy releases a startup
slot on its first stdout bytes, which is a resource hint, never an authority or
lifecycle receipt. A separate per-connection keeper survives proxy SIGKILL and
cleans its own process group/adopted descendants. Kernel pidfds prevent PID reuse.
"""
import ctypes
import fcntl
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time

LIMIT = 65536
CHUNK = 16384
_libc = ctypes.CDLL(None, use_errno=True)
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
_libc.prctl.restype = ctypes.c_int


def prctl(option, value):
    if _libc.prctl(option, value, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'supervisor kernel contract unavailable')


def _custody(path, owner, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise OSError('supervisor object custody mismatch')
    if directory and not stat.S_ISDIR(info.st_mode): raise OSError('expected directory')
    if not directory and not stat.S_ISREG(info.st_mode): raise OSError('expected regular file')


def open_slots(root, count):
    if not 1 <= count <= 2: raise ValueError('invalid startup capacity')
    if root.parent == Path('/dev/shm'):
        info = root.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777:
            raise OSError('shared tmpfs custody mismatch')
    else:
        _custody(root.parent, os.getuid(), directory=True)
    root.mkdir(mode=0o700, exist_ok=True)
    _custody(root, os.getuid(), directory=True)
    if stat.S_IMODE(root.stat().st_mode) != 0o700: raise OSError('private gate mode mismatch')
    slots = []
    try:
        for index in range(count):
            path = root/('slot-'+str(index)+'.lock')
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            slots.append(fd)
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise OSError('startup lock custody mismatch')
        return slots
    except BaseException:
        for fd in slots: os.close(fd)
        raise


def acquire(slots):
    for fd in slots:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: continue
        return fd
    return None


def close_fds(fds, keep=()):
    for fd in set(fds):
        if fd >= 0 and fd not in keep:
            try: os.close(fd)
            except OSError: pass


def _reap_tree(child, child_fd):
    # Keep the leader unreaped until killpg so its PID cannot be reused.
    try: os.killpg(child, signal.SIGKILL)
    except ProcessLookupError:
        try: os.kill(child, signal.SIGKILL)  # unreaped direct child, never a sampled PID
        except ProcessLookupError: pass
    except PermissionError: pass
    while True:
        # Only kernel-reported direct/adopted children of THIS keeper.
        path = '/proc/self/task/'+str(os.getpid())+'/children'
        try: children = [int(x) for x in Path(path).read_text().split()]
        except OSError:
            time.sleep(.05); continue  # retain custody if adoption evidence is unavailable
        for pid in children:
            try:
                handle = os.pidfd_open(pid, 0)
                try: signal.pidfd_send_signal(handle, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
                finally: os.close(handle)
            except ProcessLookupError: pass
            except OSError:
                # Kernel lists this keeper's unreaped child; even fd exhaustion
                # cannot turn cleanup into a global PID scan or release custody.
                try: os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid == 0: break
            except ChildProcessError:
                return
        # A child stuck in kernel I/O keeps custody/slot; do not claim it exited.
        time.sleep(.05)


def _keeper(command, incoming, outgoing, errors, slot, parent_fd, owner_fd, inherited):
    """Only the forked keeper runs here; no threads exist before fork."""
    child = child_fd = None
    result = 125
    custody_fds = inherited
    try:
        for sig in (signal.SIGCHLD, signal.SIGTERM, signal.SIGINT): signal.signal(sig, signal.SIG_DFL)
        prctl(36, 1)  # PR_SET_CHILD_SUBREAPER
        Path('/proc/self/task/'+str(os.getpid())+'/children').read_text()
        poll = select.poll()
        poll.register(parent_fd, select.POLLIN); poll.register(owner_fd, select.POLLIN)
        if poll.poll(0): return result  # owner died/returned before any child was created
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                expected_parent = os.getppid()
                prctl(1, signal.SIGKILL)
                if expected_parent == 1 or os.getppid() != expected_parent: os._exit(125)
                os.dup2(incoming, 0); os.dup2(outgoing, 1); os.dup2(errors, 2)
                close_fds(inherited, keep=(0, 1, 2, slot))
                os.set_inheritable(slot, True)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGPIPE): signal.signal(sig, signal.SIG_DFL)
                os.execv(command[0], command)
            except BaseException: os._exit(126)
        close_fds(inherited, keep=(parent_fd, owner_fd, slot))
        custody_fds = (parent_fd, owner_fd, slot)
        child_fd = os.pidfd_open(child, 0)
        poll.register(child_fd, select.POLLIN)
        poll.poll()  # child exit OR ownership loss; no healthy-session polling
        exited = os.waitid(os.P_PID, child, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        result = (exited.si_status if exited and exited.si_code == os.CLD_EXITED else 125)
    except BaseException:
        result = 125
    finally:
        if child is not None: _reap_tree(child, child_fd)
        close_fds(custody_fds)
        if child_fd is not None: os.close(child_fd)
    return result


def spawn(command, slot):
    allocated = []
    try:
        parent_fd = os.pidfd_open(os.getpid(), 0); allocated.append(parent_fd)
        def pipe():
            pair = os.pipe2(os.O_CLOEXEC); allocated.extend(pair); return pair
        incoming, outgoing, errors, owner = pipe(), pipe(), pipe(), pipe()
        fds = (*allocated, slot, 0, 1, 2)
        keeper = os.fork()
    except BaseException:
        close_fds(allocated); raise
    if keeper == 0:
        try: result = _keeper(command, incoming[0], outgoing[1], errors[1], slot, parent_fd, owner[0], fds)
        except BaseException: result = 125
        os._exit(result)
    close_fds((incoming[0], outgoing[1], errors[1], parent_fd, owner[0]))
    try: keeper_fd = os.pidfd_open(keeper, 0)
    except BaseException:
        close_fds(allocated)  # token EOF makes the keeper clean before reaping
        until = time.monotonic()+3
        while time.monotonic() < until:
            if os.waitpid(keeper, os.WNOHANG)[0]: break
            time.sleep(.05)
        raise
    return keeper, keeper_fd, incoming[1], outgoing[0], errors[0], owner[1]


def supervise(command, root, queue_wait=10.0, eof_grace=2.0, slots_count=2):
    slots = open_slots(root, slots_count)
    slot = None; keeper = keeper_fd = None
    child_in = child_out = child_err = owner_fd = None
    keeper_exited = False
    buffers = {'in':b'', 'out':b'', 'err':b''}
    input_open = True; output_open = {'out':True, 'err':True}
    first_output = False; eof_deadline = None
    deadline = None
    changed_flags = {}
    try:
        for fd in (0, 1, 2):
            changed_flags[fd] = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, changed_flags[fd] | os.O_NONBLOCK)
        while True:
            now = time.monotonic()
            if keeper is None and buffers['in']:
                if deadline is None: deadline = now+queue_wait
                slot = acquire(slots)
                if slot is not None:
                    close_fds(slots, keep=(slot,)); slots = [slot]
                    keeper, keeper_fd, child_in, child_out, child_err, owner_fd = spawn(command, slot)
                    for fd in (child_in, child_out, child_err): os.set_blocking(fd, False)
                elif now >= deadline: return 75
            if keeper is None and not input_open and not buffers['in']: return 0
            if eof_deadline is not None and now >= eof_deadline: return 125
            poll = select.poll()
            if input_open and len(buffers['in']) < LIMIT: poll.register(0, select.POLLIN)
            poll.register(1, select.POLLOUT if buffers['out'] else 0)
            poll.register(2, select.POLLOUT if buffers['err'] else 0)
            if keeper is not None:
                if not keeper_exited: poll.register(keeper_fd, select.POLLIN)
                if child_in is not None: poll.register(child_in, select.POLLOUT if buffers['in'] else 0)
                if child_out is not None and len(buffers['out']) < LIMIT: poll.register(child_out, select.POLLIN)
                if child_err is not None and len(buffers['err']) < LIMIT: poll.register(child_err, select.POLLIN)
            timeout = 100 if keeper is None and buffers['in'] else -1
            if eof_deadline is not None: timeout = max(0, min(100, int((eof_deadline-now)*1000)))
            for fd, event in poll.poll(timeout):
                if fd in (1, 2) and event & (select.POLLERR | select.POLLHUP): return 125
                if fd == 0 and input_open and event & (select.POLLIN | select.POLLHUP):
                    try: data = os.read(0, min(CHUNK, LIMIT-len(buffers['in'])))
                    except BlockingIOError: continue
                    if data: buffers['in'] += data
                    else:
                        input_open = False
                        if not first_output:
                            return 0 if keeper is None and not buffers['in'] else 125
                        eof_deadline = time.monotonic()+eof_grace
                elif fd == keeper_fd:
                    keeper_exited = True
                elif fd == child_in and event & (select.POLLERR | select.POLLHUP):
                    os.close(fd); child_in = None
                    buffers['in'] = b''  # child has exited/refused; preserve its exit status
                    input_open = False
                elif fd == child_in and event & select.POLLOUT and buffers['in']:
                    try: count = os.write(fd, buffers['in'][:CHUNK])
                    except BlockingIOError: continue
                    except BrokenPipeError: return 125
                    buffers['in'] = buffers['in'][count:]
                elif fd in (child_out, child_err) and event & (select.POLLIN | select.POLLHUP):
                    label = 'out' if fd == child_out else 'err'
                    try: data = os.read(fd, min(CHUNK, LIMIT-len(buffers[label])))
                    except BlockingIOError: continue
                    if data:
                        buffers[label] += data
                        if label == 'out' and not first_output:
                            fcntl.flock(slot, fcntl.LOCK_UN); first_output = True
                    else:
                        os.close(fd); output_open[label] = False
                        if label == 'out': child_out = None
                        else: child_err = None
                elif fd in (1, 2) and event & select.POLLOUT:
                    label = 'out' if fd == 1 else 'err'
                    try: count = os.write(fd, buffers[label][:CHUNK])
                    except BlockingIOError: continue
                    buffers[label] = buffers[label][count:]
            if keeper is not None and not input_open and not buffers['in'] and child_in is not None:
                os.close(child_in); child_in = None
            if keeper is not None and not any(output_open.values()) and not buffers['out'] and not buffers['err']:
                done, status = os.waitpid(keeper, os.WNOHANG)
                if done:
                    keeper = None
                    return os.waitstatus_to_exitcode(status)
    finally:
        # Function return closes the token; SIGKILL is also caught via pidfd.
        close_fds(fd for fd in (owner_fd, child_in, child_out, child_err) if fd is not None)
        if keeper is not None:
            waiter = select.poll(); waiter.register(keeper_fd, select.POLLIN)
            if waiter.poll(3000): os.waitpid(keeper, 0)
            # Kernel-stuck children retain keeper custody rather than a false PASS.
        close_fds(slots)
        if keeper_fd is not None: os.close(keeper_fd)
        for fd, flags in changed_flags.items():
            try: fcntl.fcntl(fd, fcntl.F_SETFL, flags)
            except OSError: pass


def main():
    if len(sys.argv) != 2: return 64
    script = Path(sys.argv[1]).absolute()
    _custody(script, 0); _custody(script.parent, 0, directory=True)
    if script.name != 'run-mcp-child': return 64
    # Private gate is user-owned tmpfs; no canonical data or request identity.
    root = Path('/dev/shm')/('integrity-transport-start-'+str(os.getuid()))
    # /dev/shm itself is shared; check only private root, not its intentional 1777 parent.
    return supervise(['/bin/sh', str(script)], root)


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (OSError, RuntimeError):
        print('Integrity transport supervisor unavailable', file=sys.stderr)
        raise SystemExit(125)
