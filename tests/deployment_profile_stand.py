"""Run the disposable full stand under one deployment profile (child process).

Arguments: root, repository, profile path, expected digest. The profile is
activated before any identity value is read, exactly as the server entry point
does. Prints one JSON document; never a profile value.
"""
import json
from pathlib import Path
import re
import sys

import pytest

root, repository, profile_path, expected_digest = sys.argv[1:5]
sys.path.insert(0, str(Path(repository).resolve() / "tests"))

from integrity_guardian import deployment_profile  # noqa: E402

deployment_profile.activate(deployment_profile.load_profile(Path(profile_path), expected_digest))

from recovery_stand_fixture import Stand  # noqa: E402
from integrity_guardian import memory_synapse_mcp as mcp  # noqa: E402
from integrity_guardian import replay_catalog_pool  # noqa: E402
from integrity_guardian.ledger import LedgerStore, LedgerVerificationError  # noqa: E402

patch = pytest.MonkeyPatch()
Path(root).mkdir(mode=0o700)
stand = Stand(Path(root), patch)
try:
    facade = stand.facade()
    replay, capabilities = stand.initialize(facade)
    admission = stand.admit(facade, 1, replay=replay)
    opened = stand.tool(facade, "integrity_turn_memory_open", stand.args)
    appended = stand.append(facade, admission)
    closed = stand.close_turn(facade, opened, appended)
    replay_root = stand.archroot / "context-admission-replay-v2"
    names = sorted(p.name for p in replay_root.iterdir()) if replay_root.is_dir() else []
    # The custody ledger was created under the profile tenant; the public
    # identity must be refused, exactly like an unprofiled server start.
    try:
        with LedgerStore(stand.archroot / "guardian-architecture.sqlite3",
                         tenant_id=deployment_profile.PUBLIC_IDENTITIES["architecture_tenant_id"],
                         ledger_id=mcp.CUSTODY_LEDGER_ID):
            public_identity = "accepted"
    except LedgerVerificationError:
        public_identity = "refused"
    print(json.dumps({
        "profile": deployment_profile.describe(),
        "architecture_tenant_is_profile_value": (
            mcp.architecture_tenant_id()
            != deployment_profile.PUBLIC_IDENTITIES["architecture_tenant_id"]
        ),
        "admission_write_plane": admission["write_plane"]["outcome"],
        "append_outcome": appended["receipt"].get("outcome"),
        "append_compacted": "response_compaction" in appended["receipt"],
        "close_outcome": closed["receipt"].get("outcome"),
        "recovery_max_records": capabilities.get("integrity/session-recovery", {}).get("max_records"),
        "pool_members": sum(1 for name in names if replay_catalog_pool.is_pool_name(name)),
        "pool_journals": sum(1 for name in names if replay_catalog_pool.is_journal_name(name)),
        "public_identity": public_identity,
        "event_count": stand.event_count(),
        "unknown_replay_entries": [
            name for name in names
            if not re.fullmatch(r"[a-f0-9]{64}\.(json|catalog\.sqlite3|reservation\.json)", name)
            and not replay_catalog_pool.is_pool_name(name)
            and not replay_catalog_pool.is_journal_name(name)
            and not name.startswith(".replay-")
        ],
    }, sort_keys=True))
finally:
    stand.stop()
    patch.undo()
