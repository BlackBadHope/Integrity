"""Negative seat checks that run in the root pytest suite.

Identity comes from the server seat. Tool arguments, forged headers, and a
forged principal cannot select another seat. Another owner's memory is not
readable or writable as trusted. A non-owner cannot write or approve. The
Seats fixture's protected files stay unchanged, and that check fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import anyio
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from integrity_home.host_enrollment import HostDirectory
from integrity_home.seat_policy import SeatAccessError, SeatPolicyRouter
from integrity_home.seat_registry import SeatRegistry
from integrity_home.tenant import VerifiedOAuthPrincipal
from integrity_llm_bus.bus_server import BusCore, BusError, BusSeat, serve
from integrity_llm_bus.mesh import Mesh
from integrity_llm_bus.seat_verify import GoError, GoLedger, canonical_go
from integrity_space.backend import private_path
from integrity_space.hub import build_default_server
from integrity_space.lab import provision
from integrity_space.seat_hub import (
    SeatHubError,
    SeatNoteStore,
    dispatch_seat_tool,
    wrap_peer_memory,
)


def _utc(offset_seconds: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class ProtectedFileError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _seal_private(path: Path) -> None:
    """Mark one fixture file private for this platform's custody check."""
    if os.name == "nt":
        from integrity_guardian._windows_files import set_private_directory_acl

        set_private_directory_acl(path)
        return
    os.chmod(path, 0o600)


def _require_private_dacl(directory: Path) -> None:
    """Skip when this Windows account cannot re-seal a user-only key file.

    Host enrollment writes ``host.key`` with a user-only ``(R,W)`` ACL. The
    fixture then replaces its owner and DACL, which needs WRITE_OWNER; a
    non-elevated account does not get that on such a file. The probe builds
    the same file with the same product helper and makes the same call as
    ``_seal_private``. Only access denied (WinError 5) skips; any other error
    is raised, and where the call succeeds every custody assertion still runs.
    """
    if os.name != "nt":
        return
    from integrity_guardian._windows_files import (
        WindowsFileBoundaryError,
        set_private_directory_acl,
    )
    from integrity_home.host_enrollment import _windows_user_only

    probe = directory / "dacl-capability-probe"
    probe.write_bytes(b"probe\n")
    try:
        _windows_user_only(probe)
        set_private_directory_acl(probe)
    except WindowsFileBoundaryError as err:
        if "(winerror 5)" in str(err):
            pytest.skip(
                "this Windows account cannot replace the owner and DACL of a "
                "user-only (R,W) key file: SetFileSecurityW returned WinError 5 "
                "(needs WRITE_OWNER, e.g. an elevated or CI administrator account)"
            )
        raise
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


def _symlink_or_skip(link: Path, target: str) -> None:
    """Create a symlink, skipping only when Windows lacks the privilege."""
    try:
        link.symlink_to(target)
    except OSError as err:
        if os.name == "nt" and getattr(err, "winerror", None) == 1314:
            pytest.skip(
                "cannot create a symlink: needs SeCreateSymbolicLinkPrivilege "
                "or Windows Developer Mode (WinError 1314)"
            )
        raise


def _windows_sid() -> str:
    from integrity_guardian._windows_files import current_user_sid

    return current_user_sid()


def _windows_dacl(path: Path, allow_sids: tuple[str, ...]) -> None:
    """Replace a file DACL. Used to prove the custody check fails closed."""
    import ctypes

    from integrity_guardian import _windows_files as win

    current = win.current_user_sid()
    aces = "".join(f"(A;OICI;FA;;;{sid})" for sid in allow_sids)
    sddl = f"O:{current}D:P{aces}"
    descriptor = ctypes.c_void_p()
    required = win.wintypes.DWORD()
    ok = bool(win._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, win._SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(required),
    ))
    if not ok:
        raise ProtectedFileError("unreadable")
    try:
        flags = (win._OWNER_SECURITY_INFORMATION | win._DACL_SECURITY_INFORMATION
                 | win._PROTECTED_DACL_SECURITY_INFORMATION)
        if not win._advapi32.SetFileSecurityW(str(path), flags, descriptor):
            raise ProtectedFileError("unreadable")
    finally:
        win._kernel32.LocalFree(descriptor.value)


def protected_file_check(expected: dict[str, str]) -> None:
    """Prove each protected file is still the private regular file that was snapshotted.

    Missing, linked, loose, unreadable, or changed files raise. An empty map
    raises too: there is nothing to prove, so the check does not succeed.
    POSIX privacy is the mode bits. Windows privacy is the exact protected
    DACL; ``chmod`` does not construct that DACL and is not consulted there.
    """

    if not isinstance(expected, dict) or not expected:
        raise ProtectedFileError("no protected files")
    for raw, digest in expected.items():
        path = Path(raw)
        try:
            metadata = path.lstat()
        except OSError as err:
            raise ProtectedFileError("unreadable") from err
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProtectedFileError("not a regular file")
        if os.name == "nt":
            from integrity_guardian._windows_files import (
                WindowsFileBoundaryError,
                inspect_private_directory_acl,
            )

            try:
                inspect_private_directory_acl(path)
            except WindowsFileBoundaryError as err:
                raise ProtectedFileError("mode not private") from err
        else:
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o077:
                raise ProtectedFileError("mode not private")
            if not mode & stat.S_IRUSR:
                raise ProtectedFileError("unreadable")
            try:
                private_path(path)
            except Exception as err:
                raise ProtectedFileError("custody denied") from err
        try:
            data = path.read_bytes()
        except OSError as err:
            raise ProtectedFileError("unreadable") from err
        actual = hashlib.sha256(data).hexdigest()
        if not isinstance(digest, str) or len(digest) != 64 or actual != digest:
            raise ProtectedFileError("digest mismatch")


class SeatsFixture:
    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.root = tmp_path
        lab = tmp_path / "lab"
        provision(lab)
        self.registry_path = tmp_path / "seats.sqlite3"
        registry = SeatRegistry(self.registry_path)
        registry.create_seat(
            "seat_owner", "Owner", ["read", "write", "go_approver", "admin"],
            ["team/*", "seat/seat_owner/*"],
        )
        registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
        registry.create_seat("bob", "Bob", ["read"], ["team/*", "seat/bob/*"])
        registry.create_seat("carol", "Carol", ["read", "write", "admin"], ["team/*", "seat/carol/*"])
        self.registry = registry
        self.issued = {
            seat: registry.issue_token(seat, host, _utc(600))
            for seat, host in (
                ("seat_owner", "core"),
                ("alice", "host-a"),
                ("bob", "host-b"),
                ("carol", "host-c"),
            )
        }
        self.tokens = {}
        for seat, issued in self.issued.items():
            path = tmp_path / f"{seat}.token"
            path.write_text(issued.token, encoding="utf-8")
            os.chmod(path, 0o600)
            self.tokens[seat] = path
        future = _utc(600)
        hosts = HostDirectory(tmp_path / "hosts.sqlite3")
        alice_enroll = hosts.create_token("alice", "host-a", "ssh_stdio", future)
        hosts.join(alice_enroll, tmp_path / "alice-keys")
        self.router = SeatPolicyRouter(registry)
        self.notes_path = tmp_path / "notes.sqlite3"
        self.notes = SeatNoteStore(self.notes_path)
        self.mesh = Mesh(tmp_path / "mesh.sqlite3")
        self.protected = {}
        protected_paths = [path for path in lab.rglob("*") if path.is_file()]
        protected_paths.extend([
            self.registry_path,
            tmp_path / "hosts.sqlite3",
            *self.tokens.values(),
            tmp_path / "alice-keys" / "host.key",
            tmp_path / "alice-keys" / "peer.key",
        ])
        for path in protected_paths:
            _seal_private(path)
            self.protected[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        monkeypatch.setenv("INTEGRITY_SEAT_TOKEN_FILE", str(self.tokens["alice"]))

    def use_token(self, seat: str) -> None:
        os.environ["INTEGRITY_SEAT_TOKEN_FILE"] = str(self.tokens[seat])

    def context(self, seat: str):
        return self.router.resolve_token(self.issued[seat].token, now_utc=_utc(0))

    def check(self) -> None:
        protected_file_check(self.protected)

    def server(self, **kwargs):
        return build_default_server(
            object(), object(), object(),
            name="integrity-seats-bridge",
            ui_mode="workbench",
            instructions="test",
            seat_registry=self.registry_path,
            notes=self.notes,
            mesh=self.mesh,
            **kwargs,
        )


@pytest.fixture
def seats(tmp_path, monkeypatch):
    _require_private_dacl(tmp_path)
    fixture = SeatsFixture(tmp_path, monkeypatch)
    try:
        yield fixture
    finally:
        fixture.notes.close()
        fixture.mesh.close()


def test_seat_arguments_cannot_spoof_another_seat(seats):
    bob = seats.context("bob")
    alice = seats.context("alice")
    for name, arguments in (
        ("seat_whoami", {"seat_id": "alice"}),
        ("seat_whoami", {"host_id": "core"}),
        ("seat_whoami", {"url": "https://example.invalid/alice"}),
        ("seat_append_note", {"note": "no", "seat_id": "alice", "host_id": "host-a"}),
        ("mesh_status", {"work_id": "work-1", "upstream_url": "https://example.invalid/mesh"}),
        ("bus_post_message", {"upstream_id": "example-memory", "body": "x", "url": "https://example.invalid/bus"}),
    ):
        with pytest.raises(SeatHubError) as denied:
            dispatch_seat_tool(name, arguments, bob, notes=seats.notes, router=seats.router)
        assert denied.value.status == 403
        assert denied.value.code == "identity is server-derived"

    forged = {
        "token": seats.issued["alice"].token,
        "namespace": "seat/alice/notes",
        "path": str(seats.registry_path),
        "X-Integrity-Seat-Id": "alice",
    }
    seen = dispatch_seat_tool("seat_whoami", forged, bob)
    assert seen["seat_id"] == "bob"
    assert seen["host_id"] == "host-b"
    stored = dispatch_seat_tool(
        "seat_append_note",
        {"note": "carol-note", "namespace": "seat/alice/notes", "path": str(seats.notes_path)},
        seats.context("carol"),
        notes=seats.notes,
        router=seats.router,
    )
    assert stored["seat_id"] == "carol"
    assert stored["namespace"] == "seat/carol/notes"
    assert seats.notes.read(alice) == []
    assert seats.notes.read(bob) == []


def test_forged_headers_and_identity_cannot_spoof_another_seat(seats):
    seats.use_token("alice")
    with pytest.raises(SeatAccessError) as mismatch:
        seats.router.resolve_request(header_token=seats.issued["bob"].token, now_utc=_utc(0))
    assert mismatch.value.status == 401
    bob_principal = VerifiedOAuthPrincipal(
        issuer="https://issuer.example.invalid",
        subject="bob",
        audience=("https://memory.example.invalid",),
        scopes=frozenset({"memory:read"}),
    )
    seats.registry.bind_identity(bob_principal.issuer, bob_principal.subject, "bob")
    # A verified principal does not override the seat token file.
    assert seats.router.resolve_request(principal=bob_principal, now_utc=_utc(0)).seat_id == "alice"
    os.environ["INTEGRITY_SEAT_ID"] = "bob"
    os.environ["X_INTEGRITY_SEAT_ID"] = "bob"
    assert seats.router.resolve_request(now_utc=_utc(0)).seat_id == "alice"

    class ForgedPrincipal:
        issuer = bob_principal.issuer
        subject = "alice"
        audience = bob_principal.audience
        scopes = bob_principal.scopes

    with pytest.raises(SeatAccessError) as forged:
        seats.router.resolve_principal(ForgedPrincipal())
    assert forged.value.status == 401

    server = seats.server()

    async def run():
        class ForgedCall:
            seat_id = "bob"
            host_id = "core"
            headers = {
                "X-Integrity-Seat-Id": "bob",
                "X-Integrity-Host-Id": "core",
                "X-Integrity-Seat-Token": seats.issued["bob"].token,
            }

        denied = await server.call_tool("seat_whoami", {"seat_id": "bob", "host_id": "core"}, ForgedCall())
        assert denied.is_error
        assert denied.structured_content["status"] == 403
        allowed = await server.call_tool("seat_whoami", {}, ForgedCall())
        assert allowed.structured_content["seat_id"] == "alice"
        assert allowed.structured_content["host_id"] == "host-a"

    anyio.run(run)

    bus = BusCore(
        seats.root / "bus.sqlite3",
        lambda token: {
            seats.issued["alice"].token: BusSeat("alice", "host-a", frozenset({"read", "write"}), ("team/*", "seat/alice/*")),
            seats.issued["bob"].token: BusSeat("bob", "host-b", frozenset({"read"}), ("team/*", "seat/bob/*")),
        }[token],
    )
    bus.register_agent(
        BusSeat("alice", "host-a", frozenset({"read", "write"}), ("team/*", "seat/alice/*")),
        "alice",
    )
    http = serve(bus)
    try:
        headers = Message()
        headers["X-Integrity-Seat-Id"] = "alice"
        headers["X-Integrity-Host-Id"] = "core"
        headers["X-Integrity-Seat-Token"] = seats.issued["bob"].token
        assert bus.seat_from_headers(headers).seat_id == "bob"
        with pytest.raises(BusError) as rejected:
            bus.seat_from_headers(Message())
        assert rejected.value.status == 401
        url = f"http://127.0.0.1:{http.server_address[1]}/v1/messages"
        body = json.dumps({
            "id": "forged-1",
            "from": "bob",
            "seat_id": "bob",
            "host_id": "core",
            "to": "alice",
            "k": "note",
            "th": "turn",
            "body": "pretend",
        }).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Integrity-Seat-Id": "bob",
                "X-Integrity-Host-Id": "core",
                "X-Integrity-Seat-Token": seats.issued["alice"].token,
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as response:
            urlopen(request)
        assert response.value.code == 400
        denied_write = Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Integrity-Seat-Id": "alice",
                "X-Integrity-Seat-Token": seats.issued["bob"].token,
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as write_response:
            urlopen(denied_write)
        assert write_response.value.code == 403
        assert bus.meta(bus.seat_from_headers(headers))["visible_count"] == 0
    finally:
        http.shutdown()
        bus.close()


def test_cross_owner_memory_is_untrusted_and_not_writable(seats):
    owner = seats.context("seat_owner")
    carol = seats.context("carol")
    stored = dispatch_seat_tool(
        "seat_append_note", {"note": "owner-secret"}, owner, notes=seats.notes, router=seats.router,
    )
    assert stored["stored"] is True
    assert seats.notes.read(owner)[0]["note"] == "owner-secret"
    assert seats.notes.read(carol) == []
    peered = wrap_peer_memory({"seat_id": "seat_owner", "body": "owner-secret"}, "carol")
    assert peered["trust"] == "untrusted_peer_memory"
    own = wrap_peer_memory({"seat_id": "seat_owner", "body": "owner-secret"}, "seat_owner")
    assert "trust" not in own

    with pytest.raises(SeatHubError):
        dispatch_seat_tool(
            "seat_append_note",
            {"note": "overwrite", "seat_id": "seat_owner", "namespace": "seat/seat_owner/notes"},
            carol,
            notes=seats.notes,
            router=seats.router,
        )
    dispatch_seat_tool(
        "seat_append_note",
        {"note": "carol-own", "namespace": "seat/seat_owner/notes", "path": str(seats.notes_path)},
        carol,
        notes=seats.notes,
        router=seats.router,
    )
    connection = sqlite3.connect(seats.notes_path)
    try:
        rows = connection.execute(
            "SELECT seat_id, note FROM seat_notes ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    assert rows[0] == ("seat_owner", "owner-secret")
    assert ("carol", "carol-own") in rows
    assert all(note != "overwrite" for _seat, note in rows)

    moment = datetime.now(timezone.utc)
    seats.mesh.open("seat_owner", "work-1", "shared", "team/work", now=moment)
    status = dispatch_seat_tool(
        "mesh_status", {"work_id": "work-1"}, carol, mesh=seats.mesh, router=seats.router,
    )
    assert status["seat_id"] == "seat_owner"
    assert status["trust"] == "untrusted_peer_memory"
    assert seats.mesh.status("work-1")["state"] == "open"

    _assert_action_log_isolation(seats.root)


def _assert_action_log_isolation(root: Path) -> None:
    import importlib.util
    import sys

    component = Path(__file__).resolve().parents[2] / "components/integrity-action-log"
    source = component / "src/integrity_action_log/resources"
    template = json.loads((component / "configuration.example.json").read_text(encoding="utf-8"))
    template.update(configured=True)
    template["values"] = {key: str(root / key) for key in template["values"]}
    config = root / "action-log-config.json"
    config.write_text(json.dumps(template), encoding="utf-8")
    previous = {
        name: os.environ.get(name)
        for name in (
            "INTEGRITY_ACTION_LOG_CONFIG",
            "CODEX_LOG_DB",
            "CODEX_LOG_DATA_DIR",
            "INTEGRITY_ISOLATION_MODE",
        )
    }
    os.environ["INTEGRITY_ACTION_LOG_CONFIG"] = str(config)
    os.environ["CODEX_LOG_DB"] = str(root / "shared-action-log.sqlite3")
    os.environ["CODEX_LOG_DATA_DIR"] = str(root / "action-log-data")
    os.environ["INTEGRITY_ISOLATION_MODE"] = "shared-core"
    sys.path.insert(0, str(source))
    try:
        spec = importlib.util.spec_from_file_location("seat_negative_action_log", source / "codex_action_log.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        module.ensure_db()
        owner = module.SeatView(
            "seat_owner", "core", {"read", "write", "admin"}, ("team/*", "seat/seat_owner/*"), "owner-principal",
        )
        carol = module.SeatView(
            "carol", "host-c", {"read", "write", "admin"}, ("team/*", "seat/carol/*"), "carol-principal",
        )
        with module.seat_view(owner):
            module.insert_event({
                "actor": "owner", "action": "note", "summary": "owner-secret",
                "namespace": "seat/seat_owner/notes", "event_uid": "owner-note-1",
            })
            module.insert_event({
                "actor": "owner", "action": "note", "summary": "team-visible",
                "namespace": "team/default", "event_uid": "team-note-1",
            })
        with module.seat_view(carol):
            rows = module.query_events({"since": ["all"], "limit": ["50"]})
            assert {row["namespace"] for row in rows} == {"team/default"}
            assert all(row["summary"] != "owner-secret" for row in rows)
            marked = wrap_peer_memory(rows[0], "carol")
            assert marked["trust"] == "untrusted_peer_memory"
            with pytest.raises(module.SeatAccessError):
                module.insert_event({
                    "actor": "carol", "action": "note", "summary": "replaced",
                    "namespace": "seat/seat_owner/notes", "event_uid": "owner-note-1",
                })
        with module.seat_view(owner):
            again = module.query_events({"event_uid": ["owner-note-1"], "limit": ["5"]})
        assert again[0]["summary"] == "owner-secret"
    finally:
        sys.path.remove(str(source))
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_non_owner_write_and_approval_are_rejected(seats):
    bob = seats.context("bob")
    with pytest.raises(SeatHubError) as note:
        dispatch_seat_tool("seat_append_note", {"note": "no"}, bob, notes=seats.notes, router=seats.router)
    assert note.value.status == 403
    with pytest.raises(SeatHubError) as post:
        dispatch_seat_tool(
            "bus_post_message",
            {"upstream_id": "example-memory", "body": "no"},
            bob,
            router=seats.router,
        )
    assert post.value.status == 403
    with pytest.raises(SeatAccessError) as write:
        seats.router.authorize(bob, "team/work", "write")
    assert write.value.status == 403

    moment = datetime.now(timezone.utc)
    now = _utc(0)
    seats.mesh.open("alice", "approval-1", "shared", "team/work", now=moment)
    request = seats.mesh.decision_request("alice", "approval-1", "ab" * 32, now=moment)
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    seats.registry.register_signing_key("bob-key", "bob", "Ed25519", public, now)
    payload = {
        "approver_seat": "bob",
        "key_id": "bob-key",
        "core_instance_id": "core-local",
        "msg_id": "go-bob-1",
        "th": "turn-1",
        "decision_ref": ("ab" * 32)[:12] + "-no",
        "request_digest": "ab" * 32,
        "request_seq": request["seq"],
        "action": "mesh.decision",
        "scope": "team/work",
        "created_utc": now,
        "expires_utc": _utc(60),
    }
    signature = key.sign(canonical_go(payload))
    ledger = GoLedger(seats.root / "go.sqlite3", core_instance_id="core-local")

    def lookup(seat_id, key_id):
        if seat_id != "bob" or key_id != "bob-key":
            return None
        return {"alg": "Ed25519", "public_key": public, "roles": bob.roles, "retired_at": None}

    with pytest.raises(GoError) as approval:
        ledger.consume(
            payload, signature, now=datetime.now(timezone.utc),
            decision_seq=request["seq"] + 1, lookup=lookup,
        )
    assert str(approval.value) == "go approver invalid"
    assert [row["kind"] for row in seats.mesh.events("approval-1")] == ["open", "decision-request"]


def test_seat_tools_cannot_modify_protected_fixture_files(seats):
    seats.check()
    server = seats.server()
    protected_note = next(iter(seats.protected))

    async def run():
        class ForgedCall:
            headers = {"X-Integrity-Seat-Id": "bob", "X-File-Path": protected_note}

        attacks = (
            ("seat_whoami", {"seat_id": "bob", "path": protected_note, "url": "https://example.invalid/x"}),
            ("seat_append_note", {"note": protected_note, "seat_id": "seat_owner", "path": protected_note}),
            ("mesh_status", {"work_id": "work-1", "host_id": "core", "path": protected_note}),
            ("bus_post_message", {
                "upstream_id": "https://example.invalid/integrity-seats",
                "body": protected_note,
                "url": protected_note,
            }),
        )
        for name, arguments in attacks:
            result = await server.call_tool(name, arguments, ForgedCall())
            assert result.is_error
        allowed = await server.call_tool("seat_whoami", {})
        assert allowed.structured_content["seat_id"] == "alice"
        noted = await server.call_tool("seat_append_note", {"note": "allowed-own-note"})
        assert noted.structured_content["stored"] is True

    anyio.run(run)
    seats.check()


def test_protected_file_check_fails_closed(seats):
    with pytest.raises(ProtectedFileError) as empty:
        protected_file_check({})
    assert empty.value.code == "no protected files"

    sample = Path(next(iter(seats.protected)))
    missing = dict(seats.protected)
    missing[str(seats.root / "missing-protected")] = seats.protected[str(sample)]
    with pytest.raises(ProtectedFileError) as absent:
        protected_file_check(missing)
    assert absent.value.code == "unreadable"

    directory = dict(seats.protected)
    directory[str(seats.root)] = "a" * 64
    with pytest.raises(ProtectedFileError) as folder:
        protected_file_check(directory)
    assert folder.value.code == "not a regular file"

    original = sample.read_bytes()
    try:
        if os.name == "nt":
            # Same shape as a private DACL except Administrators is replaced
            # by Users. chmod cannot express that distinction on Windows.
            _windows_dacl(sample, (_windows_sid(), "S-1-5-18", "S-1-5-32-545"))
        else:
            sample.chmod(0o644)
        with pytest.raises(ProtectedFileError) as loose:
            seats.check()
        assert loose.value.code == "mode not private"
        _seal_private(sample)
        sample.write_bytes(original + b"\n")
        _seal_private(sample)
        with pytest.raises(ProtectedFileError) as changed:
            seats.check()
        assert changed.value.code == "digest mismatch"
    finally:
        if sample.is_symlink():
            sample.unlink()
        sample.write_bytes(original)
        _seal_private(sample)

    if os.name == "nt":
        # Owner-only is not the private set, and the owner can still replace
        # the DACL. An empty DACL denies that restore (winerror 5).
        _windows_dacl(sample, (_windows_sid(),))
        expected_hidden = "mode not private"
    else:
        sample.chmod(0o000)
        expected_hidden = "unreadable"
    try:
        with pytest.raises(ProtectedFileError) as hidden:
            seats.check()
        assert hidden.value.code == expected_hidden
    finally:
        _seal_private(sample)
    seats.check()

    # Last, so a missing symlink privilege skips only this case after every
    # other fail-closed assertion above has run.
    sample.unlink()
    target = sample.with_name(sample.name + ".target")
    target.write_bytes(original)
    _seal_private(target)
    try:
        _symlink_or_skip(sample, target.name)
        with pytest.raises(ProtectedFileError) as linked:
            seats.check()
        assert linked.value.code == "not a regular file"
    finally:
        if sample.is_symlink():
            sample.unlink()
        sample.write_bytes(original)
        _seal_private(sample)
    seats.check()
