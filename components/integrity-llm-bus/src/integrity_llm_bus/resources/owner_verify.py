# SPDX-License-Identifier: BUSL-1.1
"""owner/1: verify that a bus message was signed by the owner's Windows Hello key.

All agents run as the same Windows account, so a file secret proves nothing. The owner signs with a
TPM-bound Windows Hello key that needs his PIN/biometric per signature (RSA-2048, PKCS#1 v1.5, SHA-256).
Each agent verifies against its own pinned public keys; the bus gate uses the same function at post time.

Signed bytes = b"agent-bus-owner/1\\n" + root id + b"\\n" + canonical JSON of the body without own.sig.
Root id = the message id; for a team fan-out each copy is "<root>.<recipient>" and all share one signature.
own = {"kid", "ts" (ISO with offset), "nonce" (>=16 random bytes, b64), "to" (recipient list), "sig" (b64)}.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

OWNER = "owner"
DOMAIN = b"agent-bus-owner/1\n"
CERT_DOMAIN = b"agent-bus-owner/1 session\n"
BATCH_DOMAIN = b"agent-bus-owner/1 batch\n"
BATCH_FIELDS = {"kid", "ts", "nonce", "items", "sig"}
MAX_BATCH = 8  # every copy carries the whole manifest; the signer must still check the final body <= 4096 bytes
ALLOW_SESSION = False  # v1: session mode is verified but refused at the bus gate (no owner boundary between same-user processes)
MAX_SESSION_S = 30 * 60  # design option (b); short because a same-user process could misuse a live session key
MAX_AGE_S = 15 * 60
MAX_SKEW_S = 120
NONCE_SCHEMA = ("CREATE TABLE IF NOT EXISTS owner_nonces (kid TEXT NOT NULL, nonce TEXT NOT NULL, "
                "message_id TEXT NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY (kid, nonce))")


class OwnerSignatureError(ValueError):
    pass


def load_keys(path: Path) -> dict[str, rsa.RSAPublicKey]:
    """owner_keys.json: {"keys": [{"kid": .., "spki_b64": DER SubjectPublicKeyInfo, "revoked": false}]}.
    A missing file means no owner key is enrolled: every owner message is rejected."""
    keys = {}
    if not Path(path).exists():
        return keys
    for entry in json.loads(Path(path).read_text(encoding="utf-8"))["keys"]:
        if entry.get("revoked"):
            continue
        key = serialization.load_der_public_key(base64.b64decode(entry["spki_b64"], validate=True))
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise OwnerSignatureError(f"key {entry['kid']}: RSA >= 2048 required")
        keys[entry["kid"]] = key
    return keys


def fingerprint(key: rsa.RSAPublicKey) -> str:
    """Full sha256 (64 hex) of the DER SubjectPublicKeyInfo. The owner types at least its first 16 hex
    into each agent's own chat; pin_matches() compares that prefix."""
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def pin_matches(pin: str | None, full: str) -> bool:
    """An agent's own pin (>= 16 hex, given by the owner in that agent's chat) must prefix the key fingerprint."""
    pin = (pin or "").strip().lower().replace(":", "").replace(" ", "")
    return len(pin) >= 16 and all(c in "0123456789abcdef" for c in pin) and full.startswith(pin)


def signed_bytes(message_id: str, body: dict) -> bytes:
    own = {k: v for k, v in body["data"]["own"].items() if k != "sig"}
    unsigned = {**body, "data": {**body["data"], "own": own}}
    canonical = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return DOMAIN + message_id.encode("utf-8") + b"\n" + canonical.encode("utf-8")


def _b64(value, field):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise OwnerSignatureError(f"{field} must be base64") from None


def _iso(value, field) -> int:
    try:
        when = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise OwnerSignatureError(f"{field} must be ISO 8601") from None
    if when.tzinfo is None:
        raise OwnerSignatureError(f"{field} needs a UTC offset")
    return int(when.astimezone(timezone.utc).timestamp())


def cert_bytes(kid: str, cert: dict) -> bytes:
    unsigned = {"kid": kid, "pub": cert["pub"], "nb": cert["nb"], "na": cert["na"]}
    return CERT_DOMAIN + json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")


def _session_key(own: dict, hello_key, now: int, ts: int) -> ed25519.Ed25519PublicKey:
    """Session mode (design option b): one Hello prompt signs a short-lived Ed25519 session key,
    which then signs each message. The session key lives only in the console process."""
    cert = own["cert"]
    if not isinstance(cert, dict) or set(cert) != {"pub", "nb", "na", "csig"}:
        raise OwnerSignatureError("own.cert must have exactly pub, nb, na, csig")
    nb, na = _iso(cert["nb"], "cert.nb"), _iso(cert["na"], "cert.na")
    if not 0 < na - nb <= MAX_SESSION_S:
        raise OwnerSignatureError(f"session longer than {MAX_SESSION_S // 60} min or empty")
    if not (nb - MAX_SKEW_S <= now <= na + MAX_SKEW_S and nb - MAX_SKEW_S <= ts <= na):
        raise OwnerSignatureError("message outside the session window")
    try:
        hello_key.verify(_b64(cert["csig"], "cert.csig"), cert_bytes(own["kid"], cert), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise OwnerSignatureError("session certificate not signed by the owner key") from None
    raw = _b64(cert["pub"], "cert.pub")
    if len(raw) != 32:
        raise OwnerSignatureError("cert.pub must be a raw Ed25519 key")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def verify(message: dict, keys: dict, now: int) -> dict:
    """Check signature, recipient binding and freshness. Returns the own block. Nonce reuse is checked by gate().
    Direct mode: own.sig is the Hello RSA signature. Session mode: own.cert carries a Hello-signed Ed25519 key
    and own.sig is that key's signature over the same bytes."""
    if message.get("from") != OWNER:
        raise OwnerSignatureError("not an owner message")
    try:
        body = json.loads(message["body"])
    except (ValueError, TypeError):
        raise OwnerSignatureError("owner body must be agent-bus/1 JSON") from None
    data = body.get("data") if isinstance(body, dict) else None
    own = data.get("own") if isinstance(data, dict) else None
    fields = {"kid", "ts", "nonce", "to", "re", "sig"}
    if isinstance(own, dict) and set(own) == BATCH_FIELDS:
        return _verify_batch(message, body, own, keys, now)
    if not isinstance(own, dict) or set(own) not in (fields, fields | {"cert"}):
        raise OwnerSignatureError("data.own must be direct (kid, ts, nonce, to, re, sig), session (+cert) "
                                  "or batch (kid, ts, nonce, items, sig)")
    key = keys.get(own["kid"]) if isinstance(own["kid"], str) else None
    if key is None:
        raise OwnerSignatureError("unknown or revoked owner key")
    to = own["to"]
    if not isinstance(to, list) or not to or len(set(to)) != len(to) or not all(isinstance(x, str) for x in to):
        raise OwnerSignatureError("own.to must be a non-empty list of distinct addresses")
    if message.get("to") not in to:
        raise OwnerSignatureError("recipient not covered by the owner signature")
    root = root_id(message["id"], message["to"], to)
    if message.get("reply_to") != own["re"]:  # reply_to is outside the body: bind it via the signed own.re
        raise OwnerSignatureError("reply_to must equal the signed own.re")
    nonce, sig, ts = _b64(own["nonce"], "own.nonce"), _b64(own["sig"], "own.sig"), _iso(own["ts"], "own.ts")
    if len(nonce) < 16:
        raise OwnerSignatureError("own.nonce must be at least 16 bytes")
    age = now - ts
    if age > MAX_AGE_S or age < -MAX_SKEW_S:
        raise OwnerSignatureError("owner message is stale or from the future")
    try:
        if "cert" in own:
            _session_key(own, key, now, ts).verify(sig, signed_bytes(root, body))
        else:
            key.verify(sig, signed_bytes(root, body), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise OwnerSignatureError("owner signature invalid") from None
    return {**own, "root": root, "bind": root, "fingerprint": fingerprint(key),
            "mode": "session" if "cert" in own else "direct"}


def body_hash(body: dict) -> str:
    """Batch item hash: canonical JSON of the body without data.own (each copy repeats the manifest)."""
    data = {k: v for k, v in body["data"].items() if k != "own"}
    unsigned = {**body, "data": data} if data else {k: v for k, v in body.items() if k != "data"}
    canonical = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def batch_bytes(own: dict) -> bytes:
    unsigned = {k: own[k] for k in ("kid", "ts", "nonce", "items")}
    return BATCH_DOMAIN + json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")


def _verify_batch(message: dict, body: dict, own: dict, keys: dict, now: int) -> dict:
    """Batch mode: one Hello signature over a finite manifest of exact drafts. Every copy carries the whole
    manifest; membership = this message's (root, recipient, reply_to, body hash) is one signed item."""
    key = keys.get(own["kid"]) if isinstance(own["kid"], str) else None
    if key is None:
        raise OwnerSignatureError("unknown or revoked owner key")
    items = own["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH:
        raise OwnerSignatureError(f"own.items must hold 1-{MAX_BATCH} drafts")
    roots = set()
    for item in items:
        if (not isinstance(item, dict) or set(item) != {"root", "to", "re", "h"} or not isinstance(item["root"], str)
                or not isinstance(item["to"], list) or not item["to"] or len(set(item["to"])) != len(item["to"])
                or not all(isinstance(x, str) for x in item["to"]) or not isinstance(item["h"], str)
                or (item["re"] is not None and not isinstance(item["re"], str))):
            raise OwnerSignatureError("each batch item must be {root, to[], re, h}")
        if item["root"] in roots:
            raise OwnerSignatureError("batch roots must be distinct")
        roots.add(item["root"])
    copies = [(i["root"], r) if len(i["to"]) == 1 else (f"{i['root']}.{r}", r) for i in items for r in i["to"]]
    if len(copies) != len(set(copies)):
        raise OwnerSignatureError("batch maps one message copy to two items")
    match = None
    for item in items:
        if message.get("to") in item["to"]:
            try:
                if root_id(message["id"], message["to"], item["to"]) == item["root"]:
                    match = item
                    break
            except OwnerSignatureError:
                continue
    if match is None:
        raise OwnerSignatureError("message is not a member of the signed batch")
    if message.get("reply_to") != match["re"]:
        raise OwnerSignatureError("reply_to must equal the signed batch item re")
    if body_hash(body) != match["h"]:
        raise OwnerSignatureError("message body differs from the signed batch draft")
    nonce, sig, ts = _b64(own["nonce"], "own.nonce"), _b64(own["sig"], "own.sig"), _iso(own["ts"], "own.ts")
    if len(nonce) < 16:
        raise OwnerSignatureError("own.nonce must be at least 16 bytes")
    if not -MAX_SKEW_S <= now - ts <= MAX_AGE_S:
        raise OwnerSignatureError("owner message is stale or from the future")
    signed = batch_bytes(own)
    try:
        key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise OwnerSignatureError("owner signature invalid") from None
    return {**own, "to": match["to"], "re": match["re"], "root": match["root"],
            "bind": "batch:" + hashlib.sha256(signed).hexdigest()[:40], "fingerprint": fingerprint(key), "mode": "batch"}


def root_id(message_id: str, recipient: str, to: list) -> str:
    """Single recipient: the id itself. Team fan-out: each copy is '<root>.<recipient>', one signature over root."""
    if len(to) == 1:
        return message_id
    suffix = "." + recipient
    if not message_id.endswith(suffix) or len(message_id) == len(suffix):
        raise OwnerSignatureError("team copy id must be <root>.<recipient>")
    return message_id[: -len(suffix)]


def gate(db: sqlite3.Connection, message: dict, keys: dict, now: int) -> None:
    """Bus post gate, inside the post transaction (the caller has created NONCE_SCHEMA).
    Non-owner messages pass untouched. A (kid, nonce) is bound to one root id: fan-out copies of
    the same signed message share it; any other message reusing the nonce is a replay."""
    if message.get("from") != OWNER:
        return
    own = verify(message, keys, now)  # bind = root id (direct/session) or the batch manifest digest
    if own["mode"] == "session" and not ALLOW_SESSION:
        raise OwnerSignatureError("session-signed owner messages are not accepted in v1")
    seen = db.execute("SELECT message_id FROM owner_nonces WHERE kid=? AND nonce=?", (own["kid"], own["nonce"])).fetchone()
    if seen and seen[0] != own["bind"]:
        raise OwnerSignatureError("owner nonce replayed")
    if not seen:
        db.execute("INSERT INTO owner_nonces VALUES (?,?,?,?)", (own["kid"], own["nonce"], own["bind"], now))

if __name__ == "__main__":
    _integrity_require_config()
