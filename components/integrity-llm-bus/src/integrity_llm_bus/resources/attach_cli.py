# SPDX-License-Identifier: BUSL-1.1
"""Bus attachments for agents (phase C v1): content-addressed files in state/attachments.

  python attach_cli.py put --file shot.png [--file log.png ...]   -> JSON list of {sha256,name,size,mime}
  python attach_cli.py get --sha <sha256> --out <path>            -> copies after verifying the hash

Put the returned list into the message body as data.attachments (at most MAX_ATTACH per message).
The owner console shows attachments only on messages addressed to the owner.
Runs only beside bus.py with an existing bus database in the configured state directory; .txt files
(UTF-8) are accepted as text attachments (for long messages).
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
from pathlib import Path
import argparse, hashlib, json, os, re, secrets, shutil

TYPES = {"image/png": (b"\x89PNG\r\n\x1a\n", "png"), "image/jpeg": (b"\xff\xd8\xff", "jpg"),
         "image/webp": (b"RIFF", "webp")}
TEXT_MIME, TEXT_EXT = "text/plain; charset=utf-8", "txt"
MAX_BYTES = 5 * 1024 * 1024
MAX_ATTACH = 5
SHA_RE = re.compile(r"[a-f0-9]{64}")
BUS_ROOT = Path(__file__).resolve().parent
STORE = Path(_integrity_value('state_directory')) / "attachments"


def check_root(store=STORE):
    if not (BUS_ROOT / "bus.py").is_file() or not (store.parent / "bus.sqlite3").is_file():
        raise ValueError(f"attach_cli needs bus.py beside it and a bus database in {store.parent}")


def ext_of(mime):
    return TEXT_EXT if mime == TEXT_MIME else TYPES[mime][1]


def mime_of(data, path=None):
    for mime, (sig, _) in TYPES.items():
        if data.startswith(sig) and (mime != "image/webp" or data[8:12] == b"WEBP"):
            return mime
    if path is not None and Path(path).suffix.lower() == ".txt":
        data.decode("utf-8")  # UnicodeDecodeError is a ValueError
        return TEXT_MIME
    raise ValueError("only PNG, JPG, WEBP and UTF-8 .txt are supported")


def put(paths, store=STORE):
    if not 1 <= len(paths) <= MAX_ATTACH:
        raise ValueError(f"1..{MAX_ATTACH} files per message")
    check_root(store)
    out = []
    store.mkdir(parents=True, exist_ok=True)
    for path in paths:
        data = Path(path).read_bytes()
        if not data or len(data) > MAX_BYTES:
            raise ValueError(f"{path}: empty or larger than 5 MB")
        mime = mime_of(data, path)
        digest = hashlib.sha256(data).hexdigest()
        target = store / f"{digest}.{ext_of(mime)}"
        if not target.exists():
            temp = store / f".{digest}.{secrets.token_hex(4)}.tmp"
            temp.write_bytes(data)
            os.replace(temp, target)
        name = re.sub(r"[^\w.\- ]", "_", Path(path).name)[:80].strip(" .") or "attachment"
        out.append({"sha256": digest, "name": name, "size": len(data), "mime": mime})
    return out


def get(digest, out_path, store=STORE):
    if not SHA_RE.fullmatch(digest or ""):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    check_root(store)
    for ext in [e for _, e in TYPES.values()] + [TEXT_EXT]:
        src = store / f"{digest}.{ext}"
        if src.is_file():
            if hashlib.sha256(src.read_bytes()).hexdigest() != digest:
                raise ValueError("stored attachment does not match its hash")
            shutil.copyfile(src, out_path)
            return {"sha256": digest, "path": str(Path(out_path).resolve())}
    raise ValueError("attachment not found")



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("put"); a.add_argument("--file", action="append", required=True)
    b = sub.add_parser("get"); b.add_argument("--sha", required=True); b.add_argument("--out", required=True)
    args = p.parse_args()
    try:
        result = put(args.file) if args.cmd == "put" else get(args.sha, args.out)
        print(json.dumps(result, ensure_ascii=False))
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        raise SystemExit(2)
