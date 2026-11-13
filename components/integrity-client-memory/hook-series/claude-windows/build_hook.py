# SPDX-License-Identifier: BUSL-1.1
"""Build the Windows-workstation Claude Integrity hook from base/ + patches/ (SERIES.json). Installs nothing.

python build_hook.py --out DIR [--upto A08] [--compare-live --live DIR]
- applies each unified diff strictly (exact context, no fuzz, no offset search);
- after EVERY step converts LF->CRLF where the step records it and checks the sha256 recorded in SERIES.json;
- writes DIR/integrity-client-admission.py and DIR/integrity_turn_guard.py (bytes as installed);
- --upto TAG builds a partial series into DIR with a ".upto-TAG" suffix; DIR must not be built/ or the live folder;
- --compare-live reads the installed files in --live DIR (read-only) and compares byte for byte.
There is no default output folder and no default installed folder: both are always named explicitly.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILT = "built"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def apply_strict(lines: list[str], diff: str, label: str) -> list[str]:
    out, cursor = [], 0
    dl = diff.splitlines(keepends=True)
    i = 0
    while i < len(dl) and not dl[i].startswith("@@"):
        i += 1
    while i < len(dl):
        m = HUNK.match(dl[i])
        if not m:
            raise SystemExit(f"{label}: bad hunk header {dl[i]!r}")
        start = int(m.group(1)) - (0 if m.group(2) == "0" else 1)
        if start < cursor:
            raise SystemExit(f"{label}: overlapping hunk")
        out.extend(lines[cursor:start])
        cursor = start
        i += 1
        while i < len(dl) and not dl[i].startswith("@@"):
            tag, text = dl[i][0], dl[i][1:]
            if tag in " -":
                if cursor >= len(lines) or lines[cursor] != text:
                    raise SystemExit(f"{label}: context mismatch at line {cursor + 1}")
                cursor += 1
                if tag == " ":
                    out.append(text)
            elif tag == "+":
                out.append(text)
            elif tag == "\\":
                pass
            else:
                raise SystemExit(f"{label}: bad line {dl[i]!r}")
            i += 1
    out.extend(lines[cursor:])
    return out


def crlf(lines: list[str]) -> bytes:
    return "".join(lines).replace("\n", "\r\n").encode("utf-8")


def build(part: dict, upto: str | None = None, keep_steps: dict | None = None) -> bytes:
    base = (HERE / "base" / part["file"]).read_bytes()
    if sha(base) != part["base_sha256"]:
        raise SystemExit(f"{part['file']}: base sha {sha(base)[:8]} != recorded {part['base_sha256'][:8]}")
    lines = base.decode("utf-8").replace("\r\n", "\n").splitlines(keepends=True)
    current = base
    for step in part["steps"]:
        tag = step["patch"].split("-", 1)[0]
        if upto and tag > upto and tag[0] == upto[0]:
            break
        diff = (HERE / "patches" / step["patch"]).read_text(encoding="utf-8")
        lines = apply_strict(lines, diff, step["patch"])
        current = crlf(lines) if step["crlf"] else "".join(lines).encode("utf-8")
        if sha(current) != step["post_sha256"]:
            raise SystemExit(f"{step['patch']}: result {sha(current)[:8]} != recorded {step['post_sha256'][:8]}")
        if keep_steps is not None:
            keep_steps[tag] = current
    return current


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upto")
    ap.add_argument("--out", required=True, help="output dir (required; a partial build never goes to built/)")
    ap.add_argument("--compare-live", action="store_true")
    ap.add_argument("--live", help="installed folder to compare with (read-only); required by --compare-live")
    args = ap.parse_args(argv)
    if args.compare_live and not args.live:
        ap.error("--compare-live requires --live DIR")
    series = json.loads((HERE / "SERIES.json").read_text(encoding="utf-8"))
    out = Path(args.out)
    # A partial build must never land where a full build is expected:
    # built/ holds only the full build; --upto files also get a suffix.
    if args.upto:
        refused = {(HERE / BUILT).resolve()}
        if args.live:
            refused.add(Path(args.live).resolve())
        if out.resolve() in refused:
            raise SystemExit("--upto output must not be built/ or the live folder")
    out.mkdir(parents=True, exist_ok=True)
    rc = 0
    for key in ("admission", "turn_guard"):
        part = series[key]
        data = build(part, args.upto)
        name = part["file"] + (f".upto-{args.upto}" if args.upto else "")
        (out / name).write_bytes(data)
        line = f"{name}: built {sha(data)} ({len(part['steps'])} steps, every step sha-checked) -> {out}"
        if args.compare_live and not args.upto:
            live = (Path(args.live) / part["file"]).read_bytes()
            same = live == data
            rc |= 0 if same else 1
            line += f"; live {sha(live)[:16]} -> {'BYTE-IDENTICAL' if same else 'DIFFERENT'}"
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main())
