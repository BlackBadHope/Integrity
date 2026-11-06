"""Deployment identity profile: byte-pinned host identity, public defaults intact.

Every value below is invented for the test. Activation is process-global and
must precede the first identity read, so activated behaviour is exercised in
child processes; parsing is exercised in-process without activation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from integrity_guardian import deployment_profile as dp

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent

PRIVATE = {
    "protocol": dp.PROTOCOL,
    "profile_id": "deployment:example-private",
    "production_authority": False,
    "identities": {
        "architecture_tenant_id": "tenant:example-private-architecture",
        "security_tenant_id": "tenant:example-private-security",
        "security_environment_profile_id": "environment:example-private-stdio",
        "synthetic_tenant_id": "tenant:example-private-synthetic",
    },
    "action_log_dialect": {
        "mind_projection": "example.action-log.mind-projection/v1",
        "concept_recovery": "example.action-log.concept-recovery/v1",
        "coordination_projection": "example.action-log.coordination-projection/v1",
    },
    "archive_policy": {
        "source_sha256": "0" * 64,
        "manifest_event_uid": "client:example-archive-manifest-v1",
        "message_count": 10,
        "part_count": 2,
    },
    "seed_catalog": {
        "required_event_ids": [1],
        "recall_demotions": [{"action": "example-archive-chunk", "unless_terms": ["archive"]}],
    },
    "session_recovery": {"max_records": 512},
    "replay_catalog_pool": True,
    "append_response_compaction": True,
}


def _raw(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _write(path: Path, document: dict) -> tuple[Path, str]:
    raw = _raw(document)
    path.write_bytes(raw)
    if os.name == "posix":
        path.chmod(0o644)
    return path, _digest(raw)


def test_private_profile_parses_without_touching_public_defaults():
    raw = _raw(PRIVATE)
    profile = dp.parse_profile(raw, _digest(raw))
    assert profile.profile_id == "deployment:example-private"
    assert profile.digest == _digest(raw)
    assert profile.identities["architecture_tenant_id"] == "tenant:example-private-architecture"
    # Keys the profile omits keep their public values.
    assert profile.identities["canary_tenant_id"] == dp.PUBLIC_IDENTITIES["canary_tenant_id"]
    assert profile.action_log_dialect["mind_projection"] == "example.action-log.mind-projection/v1"
    assert profile.schema_rewrites() == {
        dp.PUBLIC_IDENTITIES["security_tenant_id"]: "tenant:example-private-security",
        dp.PUBLIC_IDENTITIES["security_environment_profile_id"]: "environment:example-private-stdio",
        dp.PUBLIC_IDENTITIES["synthetic_tenant_id"]: "tenant:example-private-synthetic",
    }
    assert profile.seed_required_event_ids == (1,)
    assert profile.session_recovery_max_records == 512
    assert profile.replay_catalog_pool is True
    assert profile.append_response_compaction is True
    assert dp.PUBLIC_IDENTITIES["architecture_tenant_id"].startswith("tenant:public-")


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda d: d.update(extra=True), "unknown keys"),
        (lambda d: d.update(production_authority=True), "production authority"),
        (lambda d: d.update(protocol="integrity-guardian/deployment-profile/v0"), "protocol"),
        (lambda d: d.update(profile_id="deployment:public"), "profile id"),
        (lambda d: d["identities"].update(architecture_tenant_id="tenant:UPPER"), "architecture_tenant_id"),
        (lambda d: d["identities"].update(unknown_tenant="tenant:x"), "unknown keys"),
        (lambda d: d["action_log_dialect"].update(mind_projection="example.action-log.other/v1"),
         "mind_projection"),
        (lambda d: d["archive_policy"].update(part_count=11), "counts"),
        (lambda d: d["session_recovery"].update(max_records=0), "max_records"),
        (lambda d: d.update(replay_catalog_pool="yes"), "boolean"),
    ],
)
def test_invalid_profiles_are_refused(mutation, message):
    document = json.loads(json.dumps(PRIVATE))
    mutation(document)
    raw = _raw(document)
    with pytest.raises(dp.DeploymentProfileError, match=message):
        dp.parse_profile(raw, _digest(raw))


def test_digest_is_pinned_and_paired(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    wrong = "sha256:" + "f" * 64
    with pytest.raises(dp.DeploymentProfileError, match="digest mismatch"):
        dp.load_profile(path, wrong)
    with pytest.raises(dp.DeploymentProfileError, match="requires an expected digest"):
        dp.load_profile(path, None)
    with pytest.raises(dp.DeploymentProfileError, match="requires a deployment profile"):
        dp.load_profile(None, digest)
    assert dp.load_profile(None, None) is None
    assert dp.load_profile(path, digest).digest == digest


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode custody")
def test_group_writable_profile_is_refused(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    path.chmod(0o664)
    with pytest.raises(dp.DeploymentProfileError, match="writable"):
        dp.load_profile(path, digest)


def _child(code: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", "-c", code, *args],
        capture_output=True, text=True, timeout=120,
    )


ACTIVATED = """
import json, sys
from pathlib import Path
from integrity_guardian import deployment_profile as dp
dp.activate(dp.load_profile(Path(sys.argv[1]), sys.argv[2]))
from integrity_guardian import mind_admission, schemas, same_session_recovery
from integrity_guardian.medor_architecture import architecture_tenant_id
security = schemas.load_schema("medor-security-admission-bundle")
proposal = schemas.load_schema("adapter-action-proposal")
print(json.dumps({
    "architecture": architecture_tenant_id(),
    "synthetic": dp.identity("synthetic_tenant_id"),
    "dialect": mind_admission.predecessor_action_log_dialect()[mind_admission.MIND_PROJECTION_PROTOCOL],
    "schema_tenant": proposal["properties"]["tenant_id"]["const"],
    "security_schema": json.dumps(security, sort_keys=True),
    "max_records": same_session_recovery.max_records(),
    "describe": dp.describe(),
}))
"""


def test_activated_profile_replaces_identities_and_schema_constants(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    done = _child(ACTIVATED, str(path), digest)
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    assert result["architecture"] == "tenant:example-private-architecture"
    assert result["synthetic"] == "tenant:example-private-synthetic"
    assert result["dialect"] == "example.action-log.mind-projection/v1"
    assert result["schema_tenant"] == "tenant:example-private-synthetic"
    assert "tenant:example-private-security" in result["security_schema"]
    assert "environment:example-private-stdio" in result["security_schema"]
    assert dp.PUBLIC_IDENTITIES["security_tenant_id"] not in result["security_schema"]
    assert result["max_records"] == 512
    # The content-free description names the profile, never its values.
    assert result["describe"] == {
        "protocol": dp.PROTOCOL, "profile_id": "deployment:example-private",
        "digest": digest, "production_authority": False,
    }


LATE = """
import sys
from pathlib import Path
from integrity_guardian import deployment_profile as dp
from integrity_guardian.medor_architecture import architecture_tenant_id
architecture_tenant_id()
try:
    dp.activate(dp.load_profile(Path(sys.argv[1]), sys.argv[2]))
except dp.DeploymentProfileError as exc:
    print("refused:", exc)
"""


def test_late_activation_is_refused(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    done = _child(LATE, str(path), digest)
    assert done.returncode == 0, done.stderr
    assert "refused: deployment profile must be activated before identities are read" in done.stdout


def _bootstrap(root: Path, *profile: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", "-m", "integrity_guardian.cli", "native-trust-bootstrap",
         "--state-root", str(root / "state"), "--instance-id", "instance:example",
         "--device-id", "device:example", "--architecture-root", str(root / "architecture"),
         *profile],
        capture_output=True, text=True, timeout=120,
    )


def test_custody_created_under_profile_identity_refuses_any_other(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    flags = ("--deployment-profile", str(path), "--expected-deployment-profile-digest", digest)
    created = _bootstrap(tmp_path, *flags)
    assert created.returncode == 0, created.stderr
    assert json.loads(created.stdout)["status"] == "initialized-native"
    reopened = _bootstrap(tmp_path, *flags)
    assert reopened.returncode == 0, reopened.stderr
    assert json.loads(reopened.stdout)["status"] == "verified-existing-native"

    # The public identity (no profile) is the 7.0 dry-run failure: safe refusal.
    unprofiled = _bootstrap(tmp_path)
    assert unprofiled.returncode != 0
    assert "ledger identity does not match requested identity" in unprofiled.stderr

    other = json.loads(json.dumps(PRIVATE))
    other["identities"]["architecture_tenant_id"] = "tenant:example-other-architecture"
    other_path, other_digest = _write(tmp_path / "other.json", other)
    foreign = _bootstrap(tmp_path, "--deployment-profile", str(other_path),
                         "--expected-deployment-profile-digest", other_digest)
    assert foreign.returncode != 0
    assert "ledger identity does not match requested identity" in foreign.stderr

    tampered = _bootstrap(tmp_path, "--deployment-profile", str(path),
                          "--expected-deployment-profile-digest", other_digest)
    assert tampered.returncode != 0
    assert "deployment profile digest mismatch" in tampered.stderr


def test_server_entry_point_refuses_a_mismatched_digest(tmp_path):
    path, _ = _write(tmp_path / "profile.json", PRIVATE)
    done = subprocess.run(
        [sys.executable, "-B", "-m", "integrity_guardian.memory_synapse_mcp_protocol",
         "--catalog", str(tmp_path / "catalog.sqlite3"),
         "--architecture-root", str(tmp_path / "architecture"),
         "--snapshot-root", str(tmp_path / "snapshots"),
         "--action-log-witness-helper", str(tmp_path / "helper"),
         "--trust-profile", "personal-native",
         "--native-state-root", str(tmp_path / "state"),
         "--native-instance-id", "instance:example", "--native-device-id", "device:example",
         "--deployment-profile", str(path),
         "--expected-deployment-profile-digest", "sha256:" + "0" * 64],
        capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
    )
    assert done.returncode == 2
    assert "deployment profile rejected: deployment profile digest mismatch" in done.stderr
    assert "tenant:example-private" not in done.stderr


@pytest.mark.skipif(os.name != "posix", reason="actual POSIX custody requires the Linux stand")
def test_full_stand_runs_under_private_profile(tmp_path):
    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    done = subprocess.run(
        [sys.executable, "-B", str(HERE / "deployment_profile_stand.py"),
         str(tmp_path / "stand"), str(REPOSITORY), str(path), digest],
        capture_output=True, text=True, timeout=600,
    )
    assert done.returncode == 0, done.stderr[-4000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["profile"]["profile_id"] == "deployment:example-private"
    assert result["architecture_tenant_is_profile_value"] is True
    assert result["admission_write_plane"] == "ready"
    assert result["append_compacted"] is True
    assert result["recovery_max_records"] == 512
    assert result["pool_members"] == 1
    assert result["unknown_replay_entries"] == []
    assert result["public_identity"] == "refused"
    assert result["event_count"] == 2



SEED = """
import json, sys
from pathlib import Path
from integrity_guardian import deployment_profile as dp
if len(sys.argv) > 2:
    dp.activate(dp.load_profile(Path(sys.argv[2]), sys.argv[3]))
from integrity_guardian.seed_catalog import SeedCatalog, SeedCatalogError
events = [
    {"id": 2, "ts_utc": "2026-09-01T10:00:00Z", "actor": "agent:a", "action": "example-archive-chunk",
     "summary": "harbour inventory archive chunk", "details": {}},
    {"id": 3, "ts_utc": "2026-09-01T11:00:00Z", "actor": "agent:b", "action": "note",
     "summary": "harbour inventory checked", "details": {}},
]
result = {}
try:
    SeedCatalog(Path(sys.argv[1]) / "without-anchor" / "catalog.sqlite").import_events(
        events, source_namespace="seed://project/fixture")
    result["without_anchor"] = "imported"
except SeedCatalogError as exc:
    result["without_anchor"] = str(exc)
anchor = {"id": 1, "ts_utc": "2026-09-01T09:00:00Z", "actor": "owner", "action": "decision",
          "summary": "doctrine", "details": {}}
catalog = SeedCatalog(Path(sys.argv[1]) / "with-anchor" / "catalog.sqlite")
catalog.import_events([anchor, *events], source_namespace="seed://project/fixture")
result["verified"] = catalog.verify()["ok"]
result["plain"] = [row["event_id"] for row in catalog.search("harbour inventory")]
result["chunk_score"] = next(
    row["score"] for row in catalog.search("harbour inventory") if row["event_id"] == 2)
result["named"] = [row["event_id"] for row in catalog.search("harbour archive")]
print(json.dumps(result))
"""


def test_seed_anchor_events_and_recall_demotion_follow_the_profile(tmp_path):
    public = _child(SEED, str(tmp_path / "public"))
    assert public.returncode == 0, public.stderr
    public_result = json.loads(public.stdout)
    assert public_result["without_anchor"] == "imported"
    assert sorted(public_result["plain"]) == [1, 2, 3] or sorted(public_result["plain"]) == [2, 3]

    path, digest = _write(tmp_path / "profile.json", PRIVATE)
    private = _child(SEED, str(tmp_path / "private"), str(path), digest)
    assert private.returncode == 0, private.stderr
    result = json.loads(private.stdout)
    # Event 1 is a declared anchor and the catalog has grown past it.
    assert result["without_anchor"] == "catalog is missing a mandatory deployment anchor event"
    assert result["verified"] is True
    # The bulk archive action ranks last, at a quarter of its public score,
    # unless the query names it.
    assert result["plain"][-1] == 2
    assert result["chunk_score"] < public_result["chunk_score"]
    assert result["named"][0] == 2
