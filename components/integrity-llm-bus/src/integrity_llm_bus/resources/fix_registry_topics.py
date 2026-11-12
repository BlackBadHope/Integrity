# SPDX-License-Identifier: BUSL-1.1
"""One-off repair of mojibake registry topics (UTF-8 bytes mis-decoded as CP1251), e.g. codexcw.

Default is a dry run. --apply (r3):
- takes the registry writer lock FIRST, then a fresh backup of agents-registry.json at install time,
  and verifies the backup is byte-identical to the live file read under the same lock (sha256 reported);
- recomputes the plan under the lock from that state (never from an older preimage or an earlier dry run);
- DB mode: re-reads each row inside BEGIN IMMEDIATE and changes it only if the topic still equals the
  planned old value (a concurrent explicit topic change wins), bumps the registry generation, exports;
- post-check: everything except the planned 'topic' fields is identical to the backup.
Only 'topic' changes; addresses, threads, wake and all other fields stay identical.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

import agent_registry as ar


def repaired(topic: str) -> str | None:
    if not isinstance(topic, str) or topic.isascii():
        return None
    try:
        fixed = topic.encode("cp1251").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None
    return fixed if fixed != topic else None


def _plan_from(agents: dict) -> dict:
    return {a: {"from": e["topic"], "to": repaired(e.get("topic"))}
            for a, e in agents.items() if repaired(e.get("topic"))}


def plan(state_dir: Path) -> dict:
    return _plan_from(ar.load(state_dir))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(state_dir: Path) -> dict:
    try:
        import registry_db
        db_mode = registry_db.migrated(state_dir)
    except ImportError:
        db_mode = False
    with ar._writer(state_dir) as path:
        live_sha = _sha(path) if path.exists() else None
        changes = _plan_from(ar.load(state_dir))
        if not changes:
            return {"changed": {}, "live_sha256": live_sha}
        backup = path.with_name(path.name + ".pre-topicfix-" + time.strftime("%Y%m%dT%H%M%S"))
        shutil.copy2(path, backup)
        backup_sha = _sha(backup)
        if backup_sha != live_sha:
            raise RuntimeError("fresh backup does not match live registry; nothing changed")
        before = ar.load(state_dir)
        applied, skipped = {}, {}
        if db_mode:
            con = registry_db.connect(state_dir, timeout_ms=2000)
            try:
                con.execute("BEGIN IMMEDIATE")
                for address, change in changes.items():
                    row = con.execute("SELECT core_json FROM agents WHERE address=?", (address,)).fetchone()
                    core = json.loads(row[0]) if row else None
                    if not core or core.get("topic") != change["from"]:
                        skipped[address] = "changed-concurrently"
                        continue
                    core["topic"] = change["to"]
                    con.execute("UPDATE agents SET core_json=? WHERE address=?",
                                (json.dumps(core, ensure_ascii=False, sort_keys=True), address))
                    applied[address] = change
                if applied and hasattr(registry_db, "bump_generation"):
                    registry_db.bump_generation(con)
                con.execute("COMMIT")
            finally:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                con.close()
            registry_db.export_json(state_dir)
        else:
            data = ar._document(path)
            for address, change in changes.items():
                if data["agents"].get(address, {}).get("topic") != change["from"]:
                    skipped[address] = "changed-concurrently"
                    continue
                data["agents"][address]["topic"] = change["to"]
                applied[address] = change
            ar._save_document(path, data)
        after = ar.load(state_dir)
        expect = json.loads(json.dumps(before))
        for address, change in applied.items():
            expect[address]["topic"] = change["to"]
        if after != expect:
            raise RuntimeError(f"post-check failed: registry differs beyond topics; restore {backup}")
    return {"changed": applied, "skipped": skipped, "backup": str(backup), "backup_sha256": backup_sha,
            "store": "sqlite" if db_mode else "json"}



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-dir", type=Path, default=ar.DEFAULT_STATE)
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(apply(a.state_dir) if a.apply else {"dry_run": plan(a.state_dir)}, ensure_ascii=False))
