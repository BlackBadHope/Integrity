"""Render one ``authorized_keys`` line that binds a device key to a core release.

The line is printed, never written: the owner reviews it and appends it to the
service account's ``authorized_keys`` (removing the line revokes the device).
``restrict`` disables port, agent and X11 forwarding, PTY allocation and
``~/.ssh/rc``. ``command=`` pins the release's ``run-mcp`` and the device id;
whatever command the client requests is ignored.
"""
from __future__ import annotations

import base64
import binascii
from pathlib import PurePosixPath
import re
import struct

DEVICE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
RELEASE_PATH = re.compile(r"/[A-Za-z0-9._/+-]*/[0-9a-f]{64}\Z")
FROM_PATTERN = re.compile(r"!?[0-9A-Za-z.:*?/_-]{1,255}\Z")
DEFAULT_KEY_TYPES = frozenset({
    "ssh-ed25519", "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
})
RSA = "ssh-rsa"
MIN_RSA_BITS = 3072


class AuthorizeError(ValueError):
    pass


def _rsa_bits(blob: bytes) -> int:
    offset, parts = 0, []
    for _ in range(3):
        if offset + 4 > len(blob):
            raise AuthorizeError("truncated RSA public key")
        (size,) = struct.unpack(">I", blob[offset:offset + 4])
        parts.append(blob[offset + 4:offset + 4 + size])
        offset += 4 + size
    modulus = parts[2].lstrip(b"\0")
    return len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0


def parse_public_key(text: str, *, allow_rsa: bool = False) -> tuple[str, str]:
    """Return ``(key_type, base64_blob)`` from one OpenSSH public key line."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise AuthorizeError("expected exactly one public key line")
    fields = lines[0].split()
    if len(fields) < 2:
        raise AuthorizeError("not an OpenSSH public key line")
    key_type, blob_text = fields[0], fields[1]
    allowed = DEFAULT_KEY_TYPES | ({RSA} if allow_rsa else set())
    if key_type not in allowed:
        raise AuthorizeError(f"key type not accepted: {key_type} (options or private keys are refused)")
    try:
        blob = base64.b64decode(blob_text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AuthorizeError("public key is not valid base64") from error
    if len(blob) < 4:
        raise AuthorizeError("public key blob is truncated")
    (size,) = struct.unpack(">I", blob[:4])
    if blob[4:4 + size].decode("ascii", "replace") != key_type:
        raise AuthorizeError("public key type and blob disagree")
    if key_type == RSA and _rsa_bits(blob) < MIN_RSA_BITS:
        raise AuthorizeError(f"RSA keys need at least {MIN_RSA_BITS} bits")
    return key_type, blob_text


def authorized_line(*, release: str, public_key: str, device_id: str,
                    from_patterns: tuple[str, ...] = (), allow_rsa: bool = False) -> str:
    if not DEVICE.match(device_id):
        raise AuthorizeError("device id must match [a-z0-9][a-z0-9._-]{0,62}")
    if not RELEASE_PATH.match(release) or ".." in PurePosixPath(release).parts:
        raise AuthorizeError("release must be an absolute path ending in a 64-hex release digest")
    for pattern in from_patterns:
        if not FROM_PATTERN.match(pattern):
            raise AuthorizeError(f"from= pattern not accepted: {pattern!r}")
    key_type, blob = parse_public_key(public_key, allow_rsa=allow_rsa)
    options = ["restrict", "no-user-rc"]
    if from_patterns:
        options.append('from="' + ",".join(from_patterns) + '"')
    options.append(f'command="{release}/run-mcp --device {device_id}"')
    return f"{','.join(options)} {key_type} {blob} integrity-remote:{device_id}"
