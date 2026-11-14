"""A persistent Integrity core for one Linux account (install stage 2).

``guardian-core-instance init`` creates one private folder that holds an
Action Log database, a Seed catalog, file-backed native trust keys and the
lifecycle stores.  ``serve`` is the Guardian Memory MCP server on stdio for
that folder: it is the command an ``integrity-remote`` release runs for each
SSH session, so clients on any system reach the same core.

Each ``serve`` process starts the Action Log HTTP service on an ephemeral
loopback port with a token that exists only in that process, witnesses its own
writes by reading the Action Log database, and imports new Action Log events
into the catalog before every request.  Nothing here needs root, sudo, systemd
or a listening network port.

Limits: Linux only; one account owns the folder; the keys are files in that
folder; the audit line of the server goes to syslog or stderr.  This is not
the hardened layout of ``deploy/linux-core``.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import secrets
import shutil
import sqlite3
import stat
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__

SCHEMA = "integrity-core-instance/v1"
PROFILE = "core-instance"
MARKER = "instance.json"
ENV_HOME = "INTEGRITY_CORE_HOME"
ACTION_LOG_DISTRIBUTION = "integrity-action-log"
ACTION_LOG_VERSION = "2.11.0"
# The Action Log refuses a configuration file whose "guardian_version" is not
# exactly this value.  It is the contract of that component's configuration
# reader, not the version of this package; the marker carries __version__.
ACTION_LOG_CONFIG_GUARDIAN_VERSION = "6.1.0"
# The Action Log reads one own configuration value at import: the file that
# would hold an owner-provisioned workspace id.  The launcher points it into
# the instance and creates no such file, so the id stays "unavailable".
ACTION_LOG_WORKSPACE_VALUE = "path_b8bbeaea89e4"
ACTION_LOG_MODULE = "integrity_core_instance_action_log"
GENESIS_EVENT_UID = "client:core-instance:created"


class CoreInstanceError(RuntimeError):
    """The launcher refuses this request; the message says what to do."""


def default_home() -> Path:
    """Per-user folder outside any clone."""
    configured = os.environ.get(ENV_HOME)
    if configured:
        return Path(configured)
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "integrity-core"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise CoreInstanceError(
            "the core runs on Linux only. On Windows use guardian-local-memory, "
            "or connect this machine to a Linux core with integrity-remote"
        )


@dataclass(frozen=True)
class Paths:
    home: Path

    @property
    def marker(self) -> Path:
        return self.home / MARKER

    @property
    def action_log(self) -> Path:
        return self.home / "action-log"

    @property
    def config(self) -> Path:
        return self.action_log / "config.json"

    @property
    def database(self) -> Path:
        return self.action_log / "events.sqlite3"

    @property
    def catalog(self) -> Path:
        return self.home / "catalog.sqlite3"

    @property
    def native(self) -> Path:
        return self.home / "native"

    @property
    def architecture(self) -> Path:
        return self.home / "architecture"

    @property
    def turn_memory(self) -> Path:
        return self.architecture / "turn-memory" / "turn-memory.sqlite3"

    @property
    def snapshots(self) -> Path:
        return self.home / "snapshots"

    @property
    def lock(self) -> Path:
        return self.home / "catalog.lock"


def _private_folder(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def _write_private(path: Path, document: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def read_marker(home: Path) -> dict[str, Any]:
    marker = Path(home) / MARKER
    if marker.is_symlink() or not marker.is_file():
        raise CoreInstanceError(f"{home}: no core instance here; run: guardian-core-instance init")
    try:
        document = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CoreInstanceError(f"{marker}: unreadable instance marker") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA or document.get("profile") != PROFILE:
        raise CoreInstanceError(f"{home} is not a core instance")
    return document


def _inside_clone(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def _action_log_source() -> Path:
    try:
        installed = importlib.metadata.version(ACTION_LOG_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        raise CoreInstanceError(
            "the Action Log component is not installed; from the clone run: "
            "python -m pip install ./components/integrity-action-log"
        ) from None
    if installed != ACTION_LOG_VERSION:
        raise CoreInstanceError(
            f"{ACTION_LOG_DISTRIBUTION} {installed} is installed; this launcher is written for {ACTION_LOG_VERSION}"
        )
    spec = importlib.util.find_spec("integrity_action_log")
    if spec is None or spec.origin is None:
        raise CoreInstanceError("the Action Log package cannot be located")
    script = Path(spec.origin).resolve().parent / "resources" / "codex_action_log.py"
    if script.is_symlink() or not script.is_file():
        raise CoreInstanceError("the Action Log package has no server resource")
    return script


def _load_action_log(paths: Paths, token: str) -> Any:
    """Load the Action Log server module bound to this instance.

    The module reads its paths and token from the environment when it is
    imported, so they are set first.  The token is new for every process and
    is never written to disk or passed on a command line.
    """
    script = _action_log_source()
    os.environ["INTEGRITY_ACTION_LOG_CONFIG"] = str(paths.config)
    os.environ["CODEX_LOG_DB"] = str(paths.database)
    os.environ["CODEX_LOG_DATA_DIR"] = str(paths.action_log / "data")
    os.environ["CODEX_LOG_HOST"] = "127.0.0.1"
    os.environ["CODEX_LOG_TOKEN"] = token
    os.environ.pop("CODEX_LOG_PID_FILE", None)
    resources = str(script.parent)
    if resources not in sys.path:
        sys.path.insert(0, resources)
    spec = importlib.util.spec_from_file_location(ACTION_LOG_MODULE, script)
    if spec is None or spec.loader is None:
        raise CoreInstanceError("the Action Log server resource cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[ACTION_LOG_MODULE] = module
    spec.loader.exec_module(module)
    module.validate_runtime_auth_boundary("127.0.0.1", token)
    return module


@contextmanager
def _catalog_lock(paths: Paths) -> Iterator[None]:
    """One catalog writer at a time across the serve processes of an instance."""
    import fcntl

    descriptor = os.open(paths.lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class Core:
    """One serving process over one instance folder."""

    def __init__(self, home: Path) -> None:
        _require_linux()
        from . import memory_synapse_mcp as mcp

        self.paths = Paths(Path(home).absolute())
        self.marker = read_marker(self.paths.home)
        self._mcp = mcp
        self._http = None
        self._worker = None
        self.facade = None
        token = secrets.token_urlsafe(48)
        try:
            self._start(token)
        except BaseException:
            self.close()
            raise

    def _start(self, token: str) -> None:
        from .native_trust import NativeTrustStore
        from .seed_catalog import SeedCatalog
        from .signing import public_key_fingerprint
        from .turn_memory import TurnMemoryStore, namespace_fingerprint
        from .turn_memory_profiles import VersionedTurnMemoryService

        mcp = self._mcp
        self.action_log = _load_action_log(self.paths, token)
        self.action_log.ensure_db()
        self.paths.database.chmod(0o600)
        self.catalog = SeedCatalog(self.paths.catalog)
        self.sync()

        self._http = self.action_log.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.action_log.Handler)
        self._worker = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._worker.start()

        native = NativeTrustStore(self.paths.native, instance_id=self.marker["instance_id"])
        native.bootstrap()
        native.ensure_local_transport_device(device_id=self.marker["device_id"])
        database = native.ensure_database(tenant_id=mcp.architecture_tenant_id(), ledger_id=mcp.CUSTODY_LEDGER_ID)
        architecture = mcp.PersistentMedorArchitectureService(
            self.paths.architecture,
            keys=mcp.MedorArchitectureKeys(
                source_signer=database.source_signer,
                checkpoint_signer=database.checkpoint_signer,
            ),
            event_authority_key=native.trusted_key("event-append-issuer"),
            native_database_enrollment=database.enrollment,
            native_ledger_issuer_key=native.trusted_key("ledger-issuer"),
        )
        lts = mcp.MemorySynapseLtsService(self.catalog.path)
        namespace = namespace_fingerprint(
            source_namespace=lts.snapshot()["source_namespace"],
            trust_fingerprint=public_key_fingerprint(database.source_signer.public_key),
        )
        if not self.paths.turn_memory.exists():
            TurnMemoryStore(
                self.paths.turn_memory,
                namespace=namespace,
                signer=database.checkpoint_signer,
                identity_profile="legacy-v1",
                create=True,
            )
        turns = VersionedTurnMemoryService(
            self.paths.turn_memory,
            namespace=namespace,
            signer=database.checkpoint_signer,
            initialize_native=True,
        )
        if not turns.complete:
            raise CoreInstanceError("the Turn Memory stores of this instance are incomplete")
        self.facade = mcp.MemorySynapseMcp(
            lts,
            action_log=mcp.ActionLogClient(
                "http://127.0.0.1:" + str(self._http.server_address[1]),
                auth_token=token,
                timeout=5,
            ),
            architecture=architecture,
            action_witness=mcp.SqliteActionLogWitness(self.paths.database),
            security_admission=native.security_admission(artifact_digest=lts.package_digest()),
            native_trust=native,
            native_device_id=self.marker["device_id"],
            turn_memory=turns,
            snapshot_source=self.catalog.path,
            snapshot_root=self.paths.snapshots,
        )

    def sync(self) -> int:
        """Import the Action Log events the catalog does not have yet.

        The cursor is read from the catalog, under the lock, on every call.  A
        cursor kept in this process goes stale as soon as another session of
        the same instance imports, and this one would then read and import the
        same events again.
        """
        with _catalog_lock(self.paths):
            cursor = self.catalog.event_cursor()[1]
            with self.action_log.open_db() as database:
                database.row_factory = sqlite3.Row
                rows = database.execute("SELECT * FROM events WHERE id > ? ORDER BY id", (cursor,)).fetchall()
                if not rows:
                    return 0
                events = self.action_log.rows_to_events(rows)
            self.catalog.import_events(events)
        return len(events)

    def close(self) -> None:
        if self.facade is not None:
            self.facade.close()
            self.facade = None
        if self._http is not None:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
        if self._worker is not None:
            self._worker.join(timeout=3)
            self._worker = None


def create(home: Path) -> dict[str, Any]:
    """Create one instance; refuses a folder that is in use or inside a clone."""
    _require_linux()
    paths = Paths(Path(home).absolute())
    if _inside_clone(paths.home):
        raise CoreInstanceError(f"{paths.home} is inside a Git clone; choose a folder outside it")
    if paths.home.is_symlink() or (paths.home.exists() and (not paths.home.is_dir() or any(paths.home.iterdir()))):
        raise CoreInstanceError(f"{paths.home} exists and is not empty; nothing was changed")
    _action_log_source()
    # The folder is absent or empty here, so everything in it after this point
    # was written by this call.  A failure removes it: a half-made instance
    # would make the next init refuse the folder as "not empty".
    mode = stat.S_IMODE(paths.home.stat().st_mode) if paths.home.exists() else None
    try:
        return _create(paths)
    except BaseException:
        _discard(paths.home, mode)
        raise


def _discard(home: Path, mode: int | None) -> None:
    """Undo a failed ``create``: ``mode`` is the folder's mode before it, or None if it did not exist."""
    if mode is None:
        shutil.rmtree(home, ignore_errors=True)
        return
    for item in home.iterdir():
        if item.is_dir() and not item.is_symlink():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)
    home.chmod(mode)


def _create(paths: Paths) -> dict[str, Any]:
    _private_folder(paths.home)
    suffix = secrets.token_hex(6)
    marker = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "created_at": _now(),
        "guardian_version": __version__,
        "instance_id": "instance:core-" + suffix,
        "device_id": "device:core-" + suffix,
    }
    _write_private(paths.marker, marker)
    for folder in (paths.action_log, paths.action_log / "data", paths.architecture, paths.snapshots):
        _private_folder(folder)
    _write_private(paths.config, {
        "schema": "integrity/component-config/v1",
        "component": ACTION_LOG_DISTRIBUTION,
        "configured": True,
        "guardian_version": ACTION_LOG_CONFIG_GUARDIAN_VERSION,
        "memory_api_version": ACTION_LOG_VERSION,
        "owner_local_catalogue": None,
        "values": {ACTION_LOG_WORKSPACE_VALUE: str(paths.action_log / "workspace-id")},
    })
    action_log = _load_action_log(paths, secrets.token_urlsafe(48))
    action_log.ensure_db()
    paths.database.chmod(0o600)
    action_log.insert_event({
        "actor": "core-instance",
        "action": "agent_change_start",
        "summary": "Integrity core instance created",
        "details": {"task_id": "core-instance"},
        "tags": ["core-instance"],
        "event_uid": GENESIS_EVENT_UID,
    })
    core = Core(paths.home)
    core.close()
    return marker


def server_spec(home: Path) -> dict[str, Any]:
    """The ``--server-json`` document for ``integrity-remote core init``."""
    return {"argv": [sys.executable, "-m", "integrity_guardian.core_instance", "serve",
                     "--home", str(Path(home).absolute())]}


def serve(core: Core) -> int:
    """MCP on stdio; the catalog is brought up to date before every request."""
    from .memory_synapse_mcp_protocol import dispatch

    mcp = core._mcp
    try:
        while True:
            raw = sys.stdin.buffer.readline(mcp.MAX_REQUEST_BYTES + 1)
            if not raw:
                return 0
            try:
                core.sync()
            except (OSError, sqlite3.Error, ValueError) as exc:
                print(f"guardian-core-instance: catalog sync failed: {type(exc).__name__}", file=sys.stderr, flush=True)
            try:
                if len(raw) > mcp.MAX_REQUEST_BYTES:
                    raise ValueError("request exceeds the stdio limit")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise TypeError("request must be an object")
                response = dispatch(core.facade, message)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            if response is not None:
                sys.stdout.buffer.write(mcp.canonical_json(response) + b"\n")
                sys.stdout.buffer.flush()
    finally:
        core.close()


def _private(path: Path) -> bool:
    return stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def doctor_report(home: Path) -> dict[str, Any]:
    """Read-only check of one instance; starts no server and writes nothing."""
    checks: list[dict[str, str]] = []

    def add(name: str, result: str, detail: str) -> None:
        checks.append({"check": name, "result": result, "detail": detail})

    def report() -> dict[str, Any]:
        return {"profile": PROFILE, "passed": not any(item["result"] == "fail" for item in checks), "checks": checks}

    version = ".".join(str(part) for part in sys.version_info[:3])
    add("package", "ok", f"integrity-guardian {__version__} on Python {version} ({sys.platform})")
    try:
        _require_linux()
        _action_log_source()
        add("action-log-package", "ok", f"{ACTION_LOG_DISTRIBUTION} {ACTION_LOG_VERSION}")
    except CoreInstanceError as exc:
        add("action-log-package", "fail", str(exc))
    paths = Paths(Path(home).absolute())
    try:
        marker = read_marker(paths.home)
    except CoreInstanceError as exc:
        add("instance", "fail", str(exc))
        return report()
    add("instance", "ok", f"{paths.home}: created {marker.get('created_at')}")

    private = [paths.home, paths.marker, paths.config, paths.database]
    keys = paths.native / "native-trust" / "v1" / "keys"
    if keys.is_dir():
        private.extend(sorted(item for item in keys.rglob("*") if item.is_file()))
    exposed = [str(item.relative_to(paths.home)) or "." for item in private if item.exists() and not _private(item)]
    missing = [str(item.relative_to(paths.home)) for item in private if not item.exists()]
    if missing:
        add("files", "fail", "missing: " + ", ".join(missing))
    elif exposed:
        add("files", "fail", "readable by other accounts: " + ", ".join(exposed))
    else:
        add("files", "ok", f"{len(private)} private paths, none open to other accounts")

    top = None
    if paths.database.is_file():
        try:
            with sqlite3.connect(paths.database.as_uri() + "?mode=ro", uri=True) as database:
                count, top = database.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM events").fetchone()
            add("action-log", "ok", f"{count} events, last id {top}")
        except sqlite3.Error as exc:
            add("action-log", "fail", f"database unreadable: {type(exc).__name__}")

    from .seed_catalog import SeedCatalog, SeedCatalogError

    try:
        catalog = SeedCatalog(paths.catalog)
        catalog.verify()
        count, cursor = catalog.event_cursor()
        if top is not None and cursor < top:
            add("catalog", "warn", f"verified, {count} events; {top - cursor} newer Action Log events "
                                   "are imported at the next request")
        else:
            add("catalog", "ok", f"verified, {count} events, in step with the Action Log")
    except (SeedCatalogError, OSError, sqlite3.Error) as exc:
        add("catalog", "fail", f"catalog verification failed: {exc}")

    genesis = paths.native / "native-trust" / "v1" / "genesis.json"
    if not genesis.is_file():
        add("trust", "fail", "no native trust genesis in this instance")
    else:
        from .native_trust import NativeTrustError, NativeTrustStore

        try:
            NativeTrustStore(paths.native, instance_id=marker["instance_id"]).verify_genesis()
            add("trust", "ok", "native trust genesis verified; keys are files in this folder")
        except (NativeTrustError, OSError, ValueError, KeyError) as exc:
            add("trust", "fail", f"native trust verification failed: {type(exc).__name__}")
    add("scope", "ok", "one Linux account; not the hardened deploy/linux-core layout; memory grants no authority")
    return report()


def _print_report(report: dict[str, Any], as_json: bool) -> int:
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for item in report["checks"]:
            print(f"[{item['result']:<4}] {item['check']}: {item['detail']}")
        print("doctor: " + ("PASS" if report["passed"] else "FAIL"))
    return 0 if report["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian-core-instance", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def command(name: str, text: str) -> argparse.ArgumentParser:
        item = sub.add_parser(name, help=text)
        item.add_argument("--home", type=Path, default=None,
                          help=f"instance folder (default: ${ENV_HOME} or the per-user data folder)")
        return item

    command("init", "create the instance and print the server command for integrity-remote")
    command("server-json", "print the --server-json document for integrity-remote core init")
    command("serve", "run the core MCP server on stdio (integrity-remote starts this)")
    item = command("doctor", "read-only check of the instance (exit 1 when a check fails)")
    item.add_argument("--json", action="store_true")
    item = command("uninstall", "remove the instance folder with all its memory and keys (dry run without --yes)")
    item.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    home = (args.home or default_home()).absolute()
    try:
        if args.cmd == "init":
            marker = create(home)
            print(json.dumps({"created": str(home), "instance_id": marker["instance_id"],
                              "server": server_spec(home)}, indent=2))
            return 0
        if args.cmd == "server-json":
            read_marker(home)
            print(json.dumps(server_spec(home)))
            return 0
        if args.cmd == "doctor":
            return _print_report(doctor_report(home), args.json)
        if args.cmd == "uninstall":
            if not (home / MARKER).is_file():
                print(f"No core instance in {home}. To remove the program: "
                      "python -m pip uninstall integrity-guardian integrity-action-log")
                return 0
            read_marker(home)
            if not args.yes:
                print(f"Dry run. --yes removes {home} with every event, receipt and key in it. "
                      "Remove the authorized_keys lines of its clients yourself.")
                return 0
            shutil.rmtree(home)
            print(f"Removed {home}. Remove the authorized_keys lines of its clients yourself.")
            return 0
        core = Core(home)
    except CoreInstanceError as exc:
        print(f"guardian-core-instance: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        print(f"guardian-core-instance: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return serve(core)


if __name__ == "__main__":
    raise SystemExit(main())
