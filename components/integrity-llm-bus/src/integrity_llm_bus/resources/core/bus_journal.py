# SPDX-License-Identifier: BUSL-1.1
"""bus_journal - journal of EVERY bus request: append-only JSONL, hash chain, rotation without a break.

Files journal-YYYYMM.jsonl in journal_dir. The first record of a new month links (prev) to the last record
of the previous file, so the chain is continuous across rotation. A root timer may set chattr +a on the current
file (append only) and chattr +i on closed ones (examples/llm-bus-journal-seal). The journal holds no message
bodies or secrets: only who, to whom, when, which key, body sha256 and size, verdict. Bodies are kept in the
database archive table (no TTL).
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import fcntl, glob, hashlib, json, os, time

GENESIS = "0" * 64


def _h(prev, rec):
    body = json.dumps({k: v for k, v in rec.items() if k != "hash"}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


def _files(d):
    return sorted(glob.glob(os.path.join(d, "journal-*.jsonl")))


def _last(path):
    last = None
    with open(path, "rb") as f:
        for line in f:
            if line.strip():
                last = line
    return json.loads(last) if last else None


def _head(d):
    for p in reversed(_files(d)):
        r = _last(p)
        if r:
            return r["n"], r["hash"]
    return 0, GENESIS


def append(d, data):
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, time.strftime("journal-%Y%m.jsonl", time.gmtime()))
    lock = open(os.path.join(d, ".lock"), "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        n, prev = _head(d)
        rec = {"n": n + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "prev": prev, **data}
        rec["hash"] = _h(prev, rec)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
        return rec
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()


def verify(d):
    prev, n, total = GENESIS, 0, 0
    for p in _files(d):
        with open(p, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                r = json.loads(line)
                if r["prev"] != prev or r["n"] != n + 1 or _h(prev, r) != r["hash"]:
                    return {"ok": False, "file": os.path.basename(p), "line": i}
                prev, n = r["hash"], r["n"]; total += 1
    return {"ok": True, "records": total, "head": prev, "files": len(_files(d))}



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    import sys
    print(json.dumps(verify(sys.argv[1])))
