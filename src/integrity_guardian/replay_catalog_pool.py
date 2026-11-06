"""Derived replay catalog sharing without identity, binding or history changes.

Only exact immutable catalog bytes are shared. Logical own replay names and all
original signed/control bindings remain unchanged. Callers hold the existing
maintenance lock for promote/materialize/collect; reads never repair or mutate.
Expired logical replays are collected by the facade's existing TTL policy; a
pool member is then removed only once no alias or journal references it.
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
SQLITE = b'SQLite format 3\x00'


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


def alias_document(name, binding):
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
            'binding': dict(binding), 'pool_name': '.catalog-pool-' + binding['sha256'][7:] + '.sqlite3'}


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
    wanted = alias_document(name, binding)
    if journal:
        wanted = {'protocol': JOURNAL, 'alias': wanted, 'alias_sha256': sha(canonical(wanted))}
    if _json(raw) != wanted:
        raise PoolError('catalog-pool-own-binding-mismatch')
    return wanted['alias'] if journal else wanted


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)


class FdStore:
    """POSIX dir-fd adapter. Its root is already custody-checked by the facade."""
    def __init__(self, root, check):
        self.root, self.check = root, check

    def _open(self, name):
        if not (NAME.fullmatch(name) or POOL.fullmatch(name) or JOURNAL_NAME.fullmatch(name)):
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
            fd, details = self._open(name)
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
        temporary = '.%s.json.%s.%s.tmp' % (replay['id'], os.getpid(), time.monotonic_ns())
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
        temporary = '.%s.catalog.sqlite3.%s.%s.tmp' % (NAME.fullmatch(name)['id'], os.getpid(), time.monotonic_ns())
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
        if not is_pool_name(name):
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
    if alias != alias_document(logical, alias.get('binding')):
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
        if is_pool_name(name) and name not in references and store.age(name, now) >= grace:
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
