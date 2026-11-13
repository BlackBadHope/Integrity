# SPDX-License-Identifier: BUSL-1.1
"""One-time extraction of a hook history into a patch series (read-only on its sources).

This is the tool that produced base/, patches/ and SERIES.json, kept to show how they were derived.
The original run read dated backups of an installed hook on one workstation; those backups are not
published. Here every saved state is one file under --states DIR:

  DIR/admission/00-base.py, DIR/admission/01-notif-exemption.py, ...  (state AFTER each change)
  DIR/turn_guard/00-base.py, DIR/turn_guard/01-tg-to-ISS-011.py, ...

and it writes into --out DIR:
  base/integrity-client-admission.py, base/integrity_turn_guard.py
  patches/<A|T>NN-<name>.diff     unified diffs on LF-normalized text, one per change
  SERIES.json                     order, labels, pre/post sha256 of the files as installed
Nothing is written outside --out; the states are only read. Not rerun in this repository.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ADM = "integrity-client-admission.py"
TG = "integrity_turn_guard.py"

ADM_CHAIN = [  # (label, neutral origin)
    ("base", "local fork before the notification exemption"),
    ("notif-exemption", "harness notification banners are exempt from admission"),
    ("turn-guard-beta3", "vendored turn-close guard wired into the hook"),
    ("probefix", "memory-server probe reports evidence instead of a guess"),
    ("livefix", "longer probe timeout; gap recording for an interrupted turn"),
    ("interruptmsg", "notice for a notification inside an unfinished owner turn"),
    ("admission-gate", "admission-first gate before other tools"),
    ("broker-registration", "turn registration opened by the warm broker"),
    ("ISS-007-009", "an interrupted turn is closed with its appended event"),
    ("ISS-011", "a notification turn that changes state needs admission"),
    ("ISS-017", "Stop skips re-verification after an observed close"),
    ("ISS-018", "notice for a declined close in the next turn"),
    ("ISS-019", "a no-event close after an append is refused"),
    ("ISS-013", "lifecycle budget covers one broker reconnect"),
    ("ISS-023", "a continuation turn does not inherit an already covered change"),
    ("ISS-028", "gapped registrations are closed by later events, one per hook call"),
]
TG_CHAIN = [
    ("base", "vendored beta.3 turn guard before the admission-first gate"),
    ("tg-to-ISS-011", "admission-first gate in the turn guard"),
    ("tg-ISS-011-to-ISS-018", "a notification turn that changes state is gated"),
    ("tg-ISS-018", "explicit close instruction for a turn without an event"),
]
# Steps A16..A20 were added later, one diff at a time, by the update route of the installation
# (not published); each was recorded in SERIES.json with the same fields.


def sha(b):
    return hashlib.sha256(b).hexdigest()


def lf(raw: bytes) -> str:
    text = raw.decode("utf-8")
    norm = text.replace("\r\n", "\n")
    assert "\r" not in norm, "stray CR"
    return norm


def series(states: Path, out: Path, chain, prefix, outname):
    entries = []
    paths = [states / f"{index:02d}-{label}.py" for index, (label, _origin) in enumerate(chain)]
    base_raw = paths[0].read_bytes()
    (out / "base").mkdir(parents=True, exist_ok=True)
    (out / "base" / outname).write_bytes(base_raw)
    prev_raw = base_raw
    for index, ((name, origin), path) in enumerate(zip(chain[1:], paths[1:]), start=1):
        raw = path.read_bytes()
        diff = "".join(difflib.unified_diff(
            lf(prev_raw).splitlines(keepends=True), lf(raw).splitlines(keepends=True),
            fromfile=f"a/{outname}", tofile=f"b/{outname}", n=3))
        fname = f"{prefix}{index:02d}-{name}.diff"
        (out / "patches" / fname).write_text(diff, encoding="utf-8", newline="\n")
        entries.append({
            "patch": fname, "change": name, "origin": origin,
            "pre_sha256": sha(prev_raw), "post_sha256": sha(raw),
            "crlf": b"\r\n" in raw, "added": sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")),
            "removed": sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")),
        })
        prev_raw = raw
    return {"file": outname, "base": chain[0][1], "base_sha256": sha(base_raw),
            "base_origin": chain[0][1], "steps": entries}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--states", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    (args.out / "patches").mkdir(parents=True, exist_ok=True)
    adm = series(args.states / "admission", args.out, ADM_CHAIN, "A", ADM)
    tg = series(args.states / "turn_guard", args.out, TG_CHAIN, "T", TG)
    doc = {"protocol": "integrity-client-memory/claude-hook-series/v1", "admission": adm, "turn_guard": tg}
    (args.out / "SERIES.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    for part in (adm, tg):
        print(part["file"], part["base_sha256"][:8], "->", part["steps"][-1]["post_sha256"][:8], len(part["steps"]), "steps")
        for s in part["steps"]:
            print(f"  {s['patch']:40s} {s['pre_sha256'][:8]}->{s['post_sha256'][:8]} +{s['added']} -{s['removed']}")


if __name__ == "__main__":
    main()
