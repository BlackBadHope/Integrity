"""Derived replay catalog sharing without identity, binding or history changes.

Only exact immutable catalog bytes are shared. Logical own replay names and all
original signed/control bindings remain unchanged. Callers hold the existing
maintenance lock for promote/materialize/collect; reads never repair or mutate.
Expired logical replays are collected by the facade's existing TTL policy; a
pool member is then removed only once no alias or journal references it.

ISS-113: consecutive frozen catalogs differ in a few hundred 4 KiB pages out of
~75 000, yet every non-identical catalog used to cost a full ~300 MB member. A
member may now be stored as a page delta against one full pool member (no
chains). The logical binding (sha256 and size of the full catalog bytes) is
unchanged: a delta is reconstructed into private memory and every byte is
verified against that binding before any read uses it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time

MAX_SMALL = 4096
MAX_CATALOG = 512 * 1048576
ALIAS = 'integrity/replay-catalog-pool-alias/v1'
JOURNAL = 'integrity/replay-catalog-pool-journal/v1'
NAME = re.compile(r'(?P<id>[a-f0-9]{64})\.catalog\.sqlite3\Z')
POOL = re.compile(r'\.catalog-pool-(?P<sha>[a-f0-9]{64})\.sqlite3\Z')
JOURNAL_NAME = re.compile(r'\.(?P<id>[a-f0-9]{64})\.catalog-pool\.json\Z')
DELTA = re.compile(r'\.catalog-delta-(?P<sha>[a-f0-9]{64})\.bin\Z')
SQLITE = b'SQLite format 3\x00'
DELTA_PROTOCOL = 'integrity/replay-catalog-pool-delta/v1'
DELTA_MAGIC = b'Integrity-delta\x00'
DELTA_HEADER_AREA = 4096
DELTA_RECORD_PREFIX = 8
# A delta larger than this is not worth it: the caller writes a full member,
# which then becomes the base for the following catalogs.
MAX_DELTA = 64 * 1048576


class PoolError(OSError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def is_pool_name(name):
    return POOL.fullmatch(name) is not None


def is_journal_name(name):
    return JOURNAL_NAME.fullmatch(name) is not None


def is_delta_name(name):
    return DELTA.fullmatch(name) is not None


def is_member_name(name):
    """A shared member holding catalog bytes: a full pool file or a page delta."""
    return is_pool_name(name) or is_delta_name(name)


def alias_document(name, binding, *, delta=False):
    match = NAME.fullmatch(name)
    if (match is None or not isinstance(binding, dict)
            or set(binding) != {'protocol', 'name', 'sha256', 'bytes'}
            or binding['protocol'] != 'integrity-client/context-admission-frozen-catalog/v1'
            or binding['name'] != name
            or not isinstance(binding['sha256'], str)
            or re.fullmatch(r'sha256:[a-f0-9]{64}', binding['sha256']) is None
            or type(binding['bytes']) is not int or not 0 < binding['bytes'] <= MAX_CATALOG):
        raise PoolError('catalog-pool-binding-invalid')
    return {'protocol': ALIAS, 'replay_id': 'sha256:' + match['id'], 'logical_name': name,
            'binding': dict(binding),
            'pool_name': ('.catalog-delta-' + binding['sha256'][7:] + '.bin') if delta
            else ('.catalog-pool-' + binding['sha256'][7:] + '.sqlite3')}


def _json(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise PoolError('catalog-pool-duplicate-key')
            result[key] = value
        return result
    if len(raw) > MAX_SMALL:
        raise PoolError('catalog-pool-descriptor-limit')
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise PoolError('catalog-pool-descriptor-invalid') from exc


def parse_alias(raw, name, binding, *, journal=False):
    document = _json(raw)
    for delta in (False, True):
        wanted = alias_document(name, binding, delta=delta)
        if journal:
            wanted = {'protocol': JOURNAL, 'alias': wanted, 'alias_sha256': sha(canonical(wanted))}
        if document == wanted:
            return wanted['alias'] if journal else wanted
    raise PoolError('catalog-pool-own-binding-mismatch')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)


class FdStore:
    """POSIX dir-fd adapter. Its root is already custody-checked by the facade."""
    def __init__(self, root, check):
        self.root, self.check = root, check

    def _open(self, name):
        if not (NAME.fullmatch(name) or POOL.fullmatch(name) or JOURNAL_NAME.fullmatch(name)
                or DELTA.fullmatch(name)):
            raise PoolError('catalog-pool-name-invalid')
        fd = os.open(name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=self.root)
        try:
            details = os.fstat(fd)
            uid = os.geteuid() if hasattr(os, 'geteuid') else details.st_uid
            if (not stat.S_ISREG(details.st_mode) or details.st_uid != uid
                    or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1):
                raise PoolError('catalog-pool-file-custody')
            return fd, details
        except BaseException:
            os.close(fd)
            raise

    def prefix(self, name):
        fd, before = self._open(name)
        try:
            self.check()
            raw = os.read(fd, max(16, MAX_SMALL + 1) if before.st_size <= MAX_SMALL else 16)
            if identity(before) != identity(os.fstat(fd)):
                raise PoolError('catalog-pool-read-raced')
            return raw, before.st_size
        finally:
            os.close(fd)

    def verify(self, name, binding):
        fd, before = self._open(name)
        try:
            if before.st_size != binding['bytes']:
                raise PoolError('catalog-pool-size-mismatch')
            digest = hashlib.sha256()
            while True:
                self.check()
                raw = os.read(fd, 1048576)
                if not raw:
                    break
                digest.update(raw)
            if ('sha256:' + digest.hexdigest() != binding['sha256']
                    or identity(before) != identity(os.fstat(fd))):
                raise PoolError('catalog-pool-content-changed')
            return identity(before)
        finally:
            os.close(fd)

    def exists(self, name):
        try:
            fd, _details = self._open(name)
        except FileNotFoundError:
            return False
        os.close(fd)
        return True

    def atomic_small(self, name, raw, *, absent=False):
        if len(raw) > MAX_SMALL:
            raise PoolError('catalog-pool-descriptor-limit')
        replay = NAME.fullmatch(name) or JOURNAL_NAME.fullmatch(name)
        if replay is None:
            raise PoolError('catalog-pool-small-name-invalid')
        if absent and self.exists(name):
            raise PoolError('catalog-pool-journal-already-present')
        temporary = f".{replay['id']}.json.{os.getpid()}.{time.monotonic_ns()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=self.root)
        try:
            offset = 0
            while offset < len(raw):
                self.check()
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise PoolError('catalog-pool-descriptor-write-stalled')
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            self.check()
            if absent and self.exists(name):
                raise PoolError('catalog-pool-journal-raced')
            os.replace(temporary, name, src_dir_fd=self.root, dst_dir_fd=self.root)
            os.fsync(self.root)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.root)
            except FileNotFoundError:
                pass

    def move(self, source, destination):
        if self.exists(destination):
            raise PoolError('catalog-pool-destination-raced')
        self.check()
        os.rename(source, destination, src_dir_fd=self.root, dst_dir_fd=self.root)
        os.fsync(self.root)

    def list_names(self):
        return os.listdir(self.root)

    def _expected_leaf(self, name, expected):
        try:
            raw, _ = self.prefix(name)
        except FileNotFoundError:
            if expected is None:
                return
            raise PoolError('catalog-pool-rollback-leaf-missing')
        if expected is None or raw != expected:
            raise PoolError('catalog-pool-rollback-leaf-changed')

    def copy_catalog(self, pool_name, name, binding, expected):
        self.verify(pool_name, binding)
        self._expected_leaf(name, expected)
        temporary = f".{NAME.fullmatch(name)['id']}.catalog.sqlite3.{os.getpid()}.{time.monotonic_ns()}.tmp"
        source, before = self._open(pool_name)
        target = None
        digest, copied = hashlib.sha256(), 0
        try:
            target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=self.root)
            while True:
                self.check()
                chunk = os.read(source, 1048576)
                if not chunk:
                    break
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    self.check()
                    written = os.write(target, chunk[offset:])
                    if written <= 0:
                        raise PoolError('catalog-pool-rollback-write-stalled')
                    offset += written
                copied += len(chunk)
            if (copied != binding['bytes'] or 'sha256:' + digest.hexdigest() != binding['sha256']
                    or identity(before) != identity(os.fstat(source))):
                raise PoolError('catalog-pool-rollback-source-raced')
            os.fsync(target)
        finally:
            os.close(source)
            if target is not None:
                os.close(target)
        try:
            self._expected_leaf(name, expected)
            os.replace(temporary, name, src_dir_fd=self.root, dst_dir_fd=self.root)
            os.fsync(self.root)
            self.verify(name, binding)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.root)
            except FileNotFoundError:
                pass

    def move_catalog_to_leaf(self, pool_name, name, binding, expected):
        self.verify(pool_name, binding)
        self._expected_leaf(name, expected)
        self.check()
        os.replace(pool_name, name, src_dir_fd=self.root, dst_dir_fd=self.root)
        os.fsync(self.root)
        self.verify(name, binding)

    def remove_journal(self, name, expected):
        if not JOURNAL_NAME.fullmatch(name):
            raise PoolError('catalog-pool-rollback-remove-not-allowlisted')
        raw, _ = self.prefix(name)
        if raw != expected:
            raise PoolError('catalog-pool-rollback-journal-changed')
        self.check()
        os.unlink(name, dir_fd=self.root)
        os.fsync(self.root)


    def age(self, name, now):
        fd, details = self._open(name)
        os.close(fd)
        return max(0.0, now - details.st_mtime)

    def remove_pool(self, name):
        if not is_member_name(name):
            raise PoolError('catalog-pool-remove-not-allowlisted')
        fd, _ = self._open(name)  # custody (owner, mode, single link) before unlink
        os.close(fd)
        self.check()
        os.unlink(name, dir_fd=self.root)
        for suffix in ('-wal', '-shm'):
            # Empty side files an outside non-immutable reader may have left.
            try:
                os.unlink(name + suffix, dir_fd=self.root)
            except FileNotFoundError:
                pass


    def delta_header(self, name):
        """Parse one delta member's header and check its exact size; payload is not read."""
        if not DELTA.fullmatch(name):
            raise PoolError('catalog-pool-delta-name-invalid')
        fd, before = self._open(name)
        try:
            self.check()
            raw = os.pread(fd, DELTA_HEADER_AREA, 0)
            if identity(before) != identity(os.fstat(fd)):
                raise PoolError('catalog-pool-read-raced')
        finally:
            os.close(fd)
        return parse_delta_header(raw, name, before.st_size)

    def reconstruct(self, name, binding, out_fd):
        """Write the full catalog bytes of delta ``name`` to empty ``out_fd``; verify all of them.

        The base is hashed in full against its content address, the payload is applied
        in strictly increasing page order, and the result is read back and compared with
        the logical binding. Any difference raises; ``out_fd`` is then garbage.
        """
        header = self.delta_header(name)
        target, base = header['target'], header['base']
        if target != {'sha256': binding['sha256'], 'bytes': binding['bytes']}:
            raise PoolError('catalog-pool-delta-binding-mismatch')
        page = header['page_size']
        base_fd, base_before = self._open(base['name'])
        try:
            if base_before.st_size != base['bytes']:
                raise PoolError('catalog-pool-delta-base-changed')
            digest, offset = hashlib.sha256(), 0
            keep = min(base['bytes'], target['bytes'])
            while offset < base['bytes']:
                self.check()
                raw = os.pread(base_fd, min(1048576, base['bytes'] - offset), offset)
                if not raw:
                    raise PoolError('catalog-pool-delta-base-changed')
                digest.update(raw)
                if offset < keep:
                    _write_all(out_fd, raw[:keep - offset], offset, self.check)
                offset += len(raw)
            if ('sha256:' + digest.hexdigest() != base['sha256']
                    or identity(base_before) != identity(os.fstat(base_fd))):
                raise PoolError('catalog-pool-delta-base-changed')
        finally:
            os.close(base_fd)
        os.ftruncate(out_fd, target['bytes'])
        delta_fd, delta_before = self._open(name)
        try:
            position, previous = DELTA_HEADER_AREA, -1
            for _ in range(header['pages']):
                self.check()
                record = os.pread(delta_fd, DELTA_RECORD_PREFIX + page, position)
                if len(record) != DELTA_RECORD_PREFIX + page:
                    raise PoolError('catalog-pool-delta-truncated')
                index = int.from_bytes(record[:DELTA_RECORD_PREFIX], 'big')
                if index <= previous or (index + 1) * page > target['bytes']:
                    raise PoolError('catalog-pool-delta-record-invalid')
                _write_all(out_fd, record[DELTA_RECORD_PREFIX:], index * page, self.check)
                previous, position = index, position + len(record)
            if identity(delta_before) != identity(os.fstat(delta_fd)):
                raise PoolError('catalog-pool-read-raced')
        finally:
            os.close(delta_fd)
        digest, offset = hashlib.sha256(), 0
        while offset < target['bytes']:
            self.check()
            raw = os.pread(out_fd, min(1048576, target['bytes'] - offset), offset)
            if not raw:
                raise PoolError('catalog-pool-content-changed')
            digest.update(raw)
            offset += len(raw)
        if (os.fstat(out_fd).st_size != target['bytes']
                or 'sha256:' + digest.hexdigest() != binding['sha256']):
            raise PoolError('catalog-pool-content-changed')
        return header


def _write_all(fd, raw, offset, check):
    view = memoryview(raw)
    while view:
        check()
        written = os.pwrite(fd, view, offset)
        if written <= 0:
            raise PoolError('catalog-pool-write-stalled')
        view, offset = view[written:], offset + written


def _page_size(head):
    if len(head) < 100 or not head.startswith(SQLITE):
        return None
    value = int.from_bytes(head[16:18], 'big')
    value = 65536 if value == 1 else value
    return value if 512 <= value <= 65536 and value & (value - 1) == 0 else None


def _digest_ref(value, *, named=False):
    keys = {'name', 'sha256', 'bytes'} if named else {'sha256', 'bytes'}
    return (isinstance(value, dict) and set(value) == keys
            and isinstance(value['sha256'], str)
            and re.fullmatch(r'sha256:[a-f0-9]{64}', value['sha256']) is not None
            and type(value['bytes']) is int and 0 < value['bytes'] <= MAX_CATALOG)


def parse_delta_header(raw, name, size):
    """Exact delta header: own content address, full base member, page geometry, size."""
    if len(raw) != DELTA_HEADER_AREA or not raw.startswith(DELTA_MAGIC):
        raise PoolError('catalog-pool-delta-header-invalid')
    start = len(DELTA_MAGIC) + 4
    length = int.from_bytes(raw[len(DELTA_MAGIC):start], 'big')
    if not 0 < length <= DELTA_HEADER_AREA - start or raw[start + length:].strip(b'\0'):
        raise PoolError('catalog-pool-delta-header-invalid')
    header = _json(raw[start:start + length])
    if (not isinstance(header, dict)
            or set(header) != {'protocol', 'target', 'base', 'page_size', 'pages'}
            or header['protocol'] != DELTA_PROTOCOL
            or not _digest_ref(header['target']) or not _digest_ref(header['base'], named=True)):
        raise PoolError('catalog-pool-delta-header-invalid')
    target, base, page, pages = header['target'], header['base'], header['page_size'], header['pages']
    if (name != '.catalog-delta-' + target['sha256'][7:] + '.bin'
            or base['name'] != '.catalog-pool-' + base['sha256'][7:] + '.sqlite3'
            or type(page) is not int or not 512 <= page <= 65536 or page & (page - 1)
            or target['bytes'] % page or base['bytes'] % page
            or type(pages) is not int or not 0 <= pages <= target['bytes'] // page):
        raise PoolError('catalog-pool-delta-header-invalid')
    expected = DELTA_HEADER_AREA + pages * (DELTA_RECORD_PREFIX + page)
    if size != expected or expected > DELTA_HEADER_AREA + MAX_DELTA:
        raise PoolError('catalog-pool-delta-size-mismatch')
    return header


def write_delta_store(store, base_name, source_fd, source_size, out_fd, *, limit=MAX_DELTA):
    """Write the page delta of ``source_fd`` against full member ``base_name`` to empty ``out_fd``.

    Returns {'sha256', 'bytes', 'delta_bytes', 'pages'} for the full source bytes, or
    None when the pair does not qualify (not SQLite, other page geometry, or a delta
    over ``limit``); the caller then discards ``out_fd`` and writes a full member. The
    base is hashed in full while it is compared, so a delta never names bytes it did
    not read. The caller still verifies the source identity around this call.
    """
    match = POOL.fullmatch(base_name)
    if match is None:
        raise PoolError('catalog-pool-delta-base-invalid')
    base_fd, base_before = store._open(base_name)
    try:
        page = _page_size(os.pread(source_fd, 100, 0))
        base_size = base_before.st_size
        if (page is None or page != _page_size(os.pread(base_fd, 100, 0))
                or source_size % page or base_size % page
                or not 0 < source_size <= MAX_CATALOG or not 0 < base_size <= MAX_CATALOG):
            return None
        target_digest, base_digest = hashlib.sha256(), hashlib.sha256()
        pages = written = offset = 0
        step = page * 256
        while offset < max(source_size, base_size):
            store.check()
            want_source = max(0, min(step, source_size - offset))
            want_base = max(0, min(step, base_size - offset))
            current = os.pread(source_fd, want_source, offset) if want_source else b''
            previous = os.pread(base_fd, want_base, offset) if want_base else b''
            if len(current) != want_source or len(previous) != want_base:
                raise PoolError('catalog-pool-delta-source-raced')
            target_digest.update(current)
            base_digest.update(previous)
            for start in range(0, len(current), page):
                chunk = current[start:start + page]
                if previous[start:start + page] != chunk:
                    record = ((offset + start) // page).to_bytes(DELTA_RECORD_PREFIX, 'big') + chunk
                    if written + len(record) > limit:
                        return None
                    _write_all(out_fd, record, DELTA_HEADER_AREA + written, store.check)
                    written += len(record)
                    pages += 1
            offset += step
        if (base_digest.hexdigest() != match['sha']
                or identity(base_before) != identity(os.fstat(base_fd))):
            raise PoolError('catalog-pool-delta-base-changed')
    finally:
        os.close(base_fd)
    target = {'sha256': 'sha256:' + target_digest.hexdigest(), 'bytes': source_size}
    raw = canonical({'protocol': DELTA_PROTOCOL, 'target': target,
                     'base': {'name': base_name, 'sha256': 'sha256:' + match['sha'], 'bytes': base_size},
                     'page_size': page, 'pages': pages})
    area = DELTA_MAGIC + len(raw).to_bytes(4, 'big') + raw
    if len(area) > DELTA_HEADER_AREA:
        raise PoolError('catalog-pool-delta-header-invalid')
    _write_all(out_fd, area + b'\0' * (DELTA_HEADER_AREA - len(area)), 0, store.check)
    os.ftruncate(out_fd, DELTA_HEADER_AREA + written)
    return {**target, 'delta_bytes': DELTA_HEADER_AREA + written, 'pages': pages}


def newest_base_store(store):
    """Newest full pool member, the base for the next delta; None when there is none."""
    best = None
    for name in store.list_names():
        if not is_pool_name(name):
            continue
        try:
            fd, details = store._open(name)
        except FileNotFoundError:
            continue
        os.close(fd)
        if best is None or (details.st_mtime_ns, name) > best[0]:
            best = ((details.st_mtime_ns, name), name)
    return None if best is None else best[1]


def adopt_delta_store(store, name, binding, temporary):
    """Bind ``name`` to a page delta member; caller holds the maintenance lock.

    ``temporary`` names the caller's fsynced delta file in the same directory, used
    only when the content-addressed member is absent. The end state equals
    ``adopt_existing_pool_store`` (own journal plus alias), written only after the
    member parses, names this exact binding and its base is present. Returns False,
    leaving no new reference, whenever that precondition does not hold; the caller
    then takes the full-copy path.
    """
    alias = alias_document(name, binding, delta=True)
    journal_name = '.' + NAME.fullmatch(name)['id'] + '.catalog-pool.json'
    member = alias['pool_name']
    if store.exists(name) or store.exists(journal_name):
        return False
    if not store.exists(member):
        if temporary is None:
            return False
        store.move(temporary, member)
    header = store.delta_header(member)
    if (header['target'] != {'sha256': binding['sha256'], 'bytes': binding['bytes']}
            or not store.exists(header['base']['name'])):
        return False
    raw_alias = canonical(alias)
    store.atomic_small(journal_name, canonical({'protocol': JOURNAL, 'alias': alias,
                                                'alias_sha256': sha(raw_alias)}), absent=True)
    store.atomic_small(name, raw_alias)
    return True


def write_delta(root, base_name, source_fd, source_size, out_fd, check, *, limit=MAX_DELTA):
    return write_delta_store(_store(root, check), base_name, source_fd, source_size, out_fd, limit=limit)


def newest_base(root, check):
    return newest_base_store(_store(root, check))


def adopt_delta(root, name, binding, temporary, check):
    return adopt_delta_store(_store(root, check), name, binding, temporary)


def reconstruct(root, member, binding, out_fd, check):
    return _store(root, check).reconstruct(member, binding, out_fd)


def purge_delta_layout_store(store):
    """Explicit drained maintenance before a release without delta support runs here.

    Removes every logical replay whose alias or journal resolves to a delta member
    (record, reservation, alias leaf, journal), then every delta member. Those
    replays lose session recovery, exactly as when no reservation could be made;
    canonical Seed and full pool members are untouched. Caller owns writer drain.
    """
    names = sorted(store.list_names())
    doomed = set()
    for name in names:
        leaf, journal = NAME.fullmatch(name), JOURNAL_NAME.fullmatch(name)
        if leaf is None and journal is None:
            continue
        raw, _ = store.prefix(name)
        if leaf is not None and raw.startswith(SQLITE):
            continue
        if is_delta_name(_reference(raw, name, journal=journal is not None)):
            doomed.add((leaf or journal)['id'])
    removed = []
    for replay_hex in sorted(doomed):
        for related in (replay_hex + '.json', replay_hex + '.reservation.json',
                        replay_hex + '.catalog.sqlite3', '.' + replay_hex + '.catalog-pool.json'):
            store.check()
            try:
                os.unlink(related, dir_fd=store.root)
                removed.append(related)
            except FileNotFoundError:
                pass
    for name in names:
        if is_delta_name(name):
            store.remove_pool(name)
            removed.append(name)
    os.fsync(store.root)
    return {'status': 'DELTA_LAYOUT_PURGED', 'replays': len(doomed), 'removed': removed,
            'canonical_writes': 0}


def purge_delta_layout(root, check):
    return purge_delta_layout_store(_store(root, check))


def _store(root, check):
    return FdStore(root, check)


def _reference(raw, name, *, journal):
    """Pool named by one exact own alias or journal; anything else pins."""
    document = _json(raw)
    if journal:
        if (not isinstance(document, dict) or set(document) != {'protocol', 'alias', 'alias_sha256'}
                or document['protocol'] != JOURNAL
                or document['alias_sha256'] != sha(canonical(document['alias']))):
            raise PoolError('catalog-pool-reference-unparsed')
        alias = document['alias']
        logical = name[1:-len('.catalog-pool.json')] + '.catalog.sqlite3'
    else:
        alias, logical = document, name
    if not isinstance(alias, dict) or alias.get('protocol') != ALIAS or alias.get('logical_name') != logical:
        raise PoolError('catalog-pool-reference-unparsed')
    if alias != alias_document(logical, alias.get('binding'),
                               delta=is_delta_name(str(alias.get('pool_name', '')))):
        raise PoolError('catalog-pool-reference-unparsed')
    return alias['pool_name']


def referenced_pools(store, names):
    """Every pool any remaining logical alias or journal can still resolve to.

    An unreadable or unparsed descriptor raises, so the caller collects nothing.
    """
    references = set()
    for name in names:
        if NAME.fullmatch(name):
            raw, _ = store.prefix(name)
            if not raw.startswith(SQLITE):
                references.add(_reference(raw, name, journal=False))
        elif JOURNAL_NAME.fullmatch(name):
            raw, _ = store.prefix(name)
            references.add(_reference(raw, name, journal=True))
    # Every present delta pins its base, referenced or not: a delta is never left
    # pointing at collected bytes. An unparsable delta raises like an alias would.
    for name in names:
        if is_delta_name(name):
            try:
                references.add(store.delta_header(name)['base']['name'])
            except FileNotFoundError:
                continue
    return references


def collect_unreferenced_store(store, *, now, grace):
    """Remove pool members no alias or journal references; caller holds maintenance lock.

    Promotion writes its journal before moving bytes into the pool, under the
    same maintenance lock, so an unreferenced member is never mid-promotion.
    The grace period is an additional margin, not the safety argument.
    """
    names = sorted(store.list_names())
    references = referenced_pools(store, names)
    removed = []
    for name in names:
        if is_member_name(name) and name not in references and store.age(name, now) >= grace:
            store.remove_pool(name)
            removed.append(name)
    if removed:
        os.fsync(store.root)
    return removed


def collect_unreferenced(root, *, now, grace, check):
    return collect_unreferenced_store(_store(root, check), now=now, grace=grace)


def resolve(store, name, binding):
    """Read-only resolution; journal recovery never replays an external action."""
    try:
        raw, _ = store.prefix(name)
    except FileNotFoundError:
        match = NAME.fullmatch(name)
        if match is None:
            raise PoolError('catalog-pool-name-invalid')
        journal = '.' + match['id'] + '.catalog-pool.json'
        raw, _ = store.prefix(journal)
        return parse_alias(raw, name, binding, journal=True)['pool_name']
    if raw.startswith(SQLITE):
        return name
    return parse_alias(raw, name, binding)['pool_name']


def resolve_name(root, name, binding, check):
    return resolve(_store(root, check), name, binding)


def logical_size(root, name, binding, actual_size, check):
    store = _store(root, check)
    resolved = resolve(store, name, binding)
    if resolved == name:
        return actual_size
    # The original opening path still validates full bytes/SHA before replay.
    # Accounting requires at least an exact own alias and a custody/size-checked pool.
    if is_delta_name(resolved):
        header = store.delta_header(resolved)
        if header['target'] != {'sha256': binding['sha256'], 'bytes': binding['bytes']}:
            raise PoolError('catalog-pool-accounting-size-mismatch')
        return binding['bytes']
    _, size = store.prefix(resolved)
    if size != binding['bytes']:
        raise PoolError('catalog-pool-accounting-size-mismatch')
    return size


def promote_store(store, name, binding):
    """Caller holds shared maintenance lock; journal precedes any replacement."""
    alias = alias_document(name, binding)
    raw_alias = canonical(alias)
    journal_name = '.' + NAME.fullmatch(name)['id'] + '.catalog-pool.json'
    journal_raw = canonical({'protocol': JOURNAL, 'alias': alias, 'alias_sha256': sha(raw_alias)})
    existing = store.exists(journal_name)
    if existing:
        raw, _ = store.prefix(journal_name)
        parse_alias(raw, name, binding, journal=True)
    else:
        store.verify(name, binding)
        store.atomic_small(journal_name, journal_raw, absent=True)
    pool = alias['pool_name']
    if store.exists(pool):
        store.verify(pool, binding)
    else:
        # No full second catalog copy and no hardlink. A crash here is resolved
        # read-only by the exact own journal; the pool bytes are already durable.
        store.verify(name, binding)
        store.move(name, pool)
        store.verify(pool, binding)
    if store.exists(name):
        raw, _ = store.prefix(name)
        if raw.startswith(SQLITE):
            store.verify(name, binding)
        else:
            parse_alias(raw, name, binding)
    store.atomic_small(name, raw_alias)
    return {'protocol': ALIAS, 'logical_name': name, 'pool_name': pool, 'binding_unchanged': True}


def adopt_existing_pool_store(store, name, binding):
    """Bind ``name`` to a pool that already holds exactly these bytes; caller holds the lock.

    The pool is content addressed by ``binding['sha256']``. When it is present and its
    full bytes verify, the end state equals ``promote_store`` for an existing pool (own
    journal plus alias) without first writing a second full copy under ``name``.
    Returns False, writing nothing, whenever that exact precondition does not hold;
    the caller then takes the original copy-and-promote path.
    """
    alias = alias_document(name, binding)
    journal_name = '.' + NAME.fullmatch(name)['id'] + '.catalog-pool.json'
    if not store.exists(alias['pool_name']) or store.exists(name) or store.exists(journal_name):
        return False
    store.verify(alias['pool_name'], binding)
    raw_alias = canonical(alias)
    store.atomic_small(journal_name, canonical({'protocol': JOURNAL, 'alias': alias,
                                                'alias_sha256': sha(raw_alias)}), absent=True)
    store.atomic_small(name, raw_alias)
    return True


def adopt_existing_pool(root, name, binding, check):
    return adopt_existing_pool_store(_store(root, check), name, binding)

def promote(root, name, binding, check):
    return promote_store(_store(root, check), name, binding)


def rollback_projection(catalogs, other_charged_bytes, *, limit=4 * 1024 ** 3):
    """Compute original-layout charge without changing any retention/TTL.

    Materialize groups by copying while >1 alias remains and RENAMING the pool
    into the last logical leaf. This bounds catalog peak by expanded layout,
    plus small descriptor temporaries; no hardlink or canonical rewrite.
    The operator must prove all-writer drain and every full catalog digest.
    """
    seen, groups = set(), {}
    expanded = int(other_charged_bytes)
    if type(other_charged_bytes) is not int or other_charged_bytes < 0:
        raise PoolError('catalog-pool-accounting-invalid')
    for row in catalogs:
        alias = alias_document(row['name'], row['binding'])
        if row['name'] in seen:
            raise PoolError('catalog-pool-logical-alias-duplicate')
        seen.add(row['name'])
        expanded += row['binding']['bytes']
        groups.setdefault(alias['pool_name'], []).append(row['name'])
    # These temporary metadata bytes are never excused from the fixed quota.
    peak = expanded + MAX_SMALL
    if peak > limit:
        raise PoolError('catalog-pool-old-layout-rollback-over-budget')
    return {'expanded_charge_bytes': expanded, 'peak_charge_bytes': peak,
            'unchanged_limit_bytes': limit, 'groups': groups,
            'materialization_order': 'copy until one alias remains; last alias moves the pool',
            'writer_drain_required': True, 'canonical_writes': 0, 'live_execution': False}


def materialize_store(store, catalogs, other_charged_bytes, *, limit=4 * 1024 ** 3):
    """Explicit drained maintenance only; restore old-reader layout, not history.

    Every logical binding, pool hash and journal is verified before first write.
    An unlisted pool/journal, unknown postimage or over-budget projection refuses
    the entire operation. The caller owns GO, all-writer drain and outer journal.
    """
    if any(is_delta_name(name) for name in store.list_names()):
        # Delta-backed replays are derived and short-lived; purge_delta_layout_store
        # retires them first instead of expanding each into a full catalog here.
        raise PoolError('catalog-pool-delta-layout-purge-first')
    projection = rollback_projection(catalogs, other_charged_bytes, limit=limit)
    groups, journals, allowed_pool, allowed_journal = {}, {}, set(), set()
    provided_names = {row['name'] for row in catalogs}
    for row in catalogs:
        name, binding = row['name'], row['binding']
        alias = alias_document(name, binding)
        journal_name = '.' + NAME.fullmatch(name)['id'] + '.catalog-pool.json'
        allowed_pool.add(alias['pool_name'])
        allowed_journal.add(journal_name)
        if store.exists(journal_name):
            journal_raw, _ = store.prefix(journal_name)
            parse_alias(journal_raw, name, binding, journal=True)
            journals[journal_name] = journal_raw
        resolved = resolve(store, name, binding)
        store.verify(resolved, binding)
        if resolved == name:
            continue
        try:
            expected, _ = store.prefix(name)
            parse_alias(expected, name, binding)
        except FileNotFoundError:
            expected = None  # exact journal already proved read-only recovery.
        groups.setdefault(resolved, []).append((name, binding, expected))
    for name in store.list_names():
        if NAME.fullmatch(name) and name not in provided_names:
            # A valid omitted alias still owns a reference even if its journal
            # is absent. Unknown non-SQLite leaves are pinned too, never guessed.
            raw, _ = store.prefix(name)
            if not raw.startswith(SQLITE):
                raise PoolError('catalog-pool-unlisted-logical-alias-pinned')
        if is_pool_name(name) and (name not in allowed_pool or name not in groups):
            raise PoolError('catalog-pool-unlisted-or-unreferenced-pool-pinned')
        if is_journal_name(name) and name not in allowed_journal:
            raise PoolError('catalog-pool-unlisted-journal-pinned')
    materialized = 0
    for pool_name, rows in sorted(groups.items()):
        for index, (name, binding, expected) in enumerate(rows):
            if index == len(rows) - 1:
                store.move_catalog_to_leaf(pool_name, name, binding, expected)
            else:
                store.copy_catalog(pool_name, name, binding, expected)
            materialized += 1
    for journal_name, expected in sorted(journals.items()):
        store.remove_journal(journal_name, expected)
    if any(is_pool_name(n) or is_journal_name(n) for n in store.list_names()):
        raise PoolError('catalog-pool-old-reader-layout-not-complete')
    return {**projection, 'status': 'OLD_CATALOG_LAYOUT_MATERIALIZED', 'materialized': materialized,
            'canonical_or_control_record_writes': 0, 'hardlinks_used': False}


def materialize(root, catalogs, other_charged_bytes, check, *, limit=4 * 1024 ** 3):
    return materialize_store(_store(root, check), catalogs, other_charged_bytes, limit=limit)
