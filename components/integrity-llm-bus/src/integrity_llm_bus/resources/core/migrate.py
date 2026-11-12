#!/usr/bin/python3 -I
# SPDX-License-Identifier: BUSL-1.1
"""migrate.py SRC_SQLITE DST_STATE_DIR - move bus history to the hub without loss, with verification.

1) SQLite online backup from a copy of the client database (taken while relay and bridge are stopped:
   flags RELAY_STOP and STOP);
2) per-table check: row count and sha256 of all rows in key order (source = destination);
3) message body archive without TTL: table messages_archive + AFTER INSERT trigger on messages;
   existing messages are copied into the archive at once. TTL deletion does not touch the archive.
Prints a JSON report; on any mismatch rc=1 and the destination must not be used.
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib, json, os, sqlite3, sys

ARCHIVE = """
CREATE TABLE IF NOT EXISTS messages_archive (
  id TEXT PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL, reply_to TEXT,
  delivery TEXT, created_at INTEGER NOT NULL, archived_at INTEGER NOT NULL, body_sha256 TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS messages_archive_ai AFTER INSERT ON messages BEGIN
  INSERT OR IGNORE INTO messages_archive(id, sender, recipient, body, reply_to, delivery, created_at, archived_at, body_sha256)
  VALUES (NEW.id, NEW.sender, NEW.recipient, NEW.body, NEW.reply_to, NEW.delivery, NEW.created_at, CAST(strftime('%s','now') AS INTEGER), '');
END;
"""


def table_digest(db, t):
    cols = [r[1] for r in db.execute(f"pragma table_info({t})")]
    pk = [r[1] for r in sorted(db.execute(f"pragma table_info({t})"), key=lambda r: r[5]) if r[5]] or cols
    h = hashlib.sha256(); n = 0
    for row in db.execute(f"select {','.join(cols)} from {t} order by {','.join(pk)}"):
        h.update(json.dumps(row, ensure_ascii=False, default=str).encode()); n += 1
    return n, h.hexdigest()


def main(src, dst_dir):
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, "bus.sqlite3")
    if os.path.exists(dst):
        print(json.dumps({"error": "destination exists; refusing to overwrite"})); return 2
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True); d = sqlite3.connect(dst)
    s.backup(d)
    tables = [r[0] for r in s.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
    report, ok = {}, True
    for t in tables:
        a, b = table_digest(s, t), table_digest(d, t)
        report[t] = {"rows": a[0], "sha256": a[1][:16], "match": a == b}
        ok &= a == b
    d.executescript(ARCHIVE)
    d.execute("INSERT OR IGNORE INTO messages_archive SELECT id, sender, recipient, body, reply_to, delivery, created_at,"
              " CAST(strftime('%s','now') AS INTEGER), '' FROM messages")
    d.commit()
    arch = d.execute("select count(*) from messages_archive").fetchone()[0]
    report["_archive_rows"] = arch; report["_archive_matches_messages"] = arch == report.get("messages", {}).get("rows")
    ok &= report["_archive_matches_messages"]
    d.execute("pragma journal_mode=WAL"); d.close(); s.close()
    print(json.dumps({"ok": ok, "tables": report}, ensure_ascii=False, indent=1))
    return 0 if ok else 1



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
