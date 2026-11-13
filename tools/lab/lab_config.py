# SPDX-License-Identifier: BUSL-1.1
"""One configuration source for the lab tools.

Values that depend on the operator's machine (paths, guest names, addresses,
pins of a particular lab build) are read from ``lab.json``. The file is found
through the ``INTEGRITY_LAB_CONFIG`` environment variable, else next to this
module, else one directory up (the lab root). ``lab.example.json`` lists every
key with a placeholder value. A missing key fails closed with a clear message.
"""
from pathlib import Path
import json
import os

HERE = Path(__file__).resolve().parent
ENVIRONMENT = 'INTEGRITY_LAB_CONFIG'
EXAMPLE = 'lab.example.json'
_loaded = None


def location():
    configured = os.environ.get(ENVIRONMENT)
    if configured:
        return Path(configured)
    for candidate in (HERE/'lab.json', HERE.parent/'lab.json'):
        if candidate.is_file():
            return candidate
    raise LookupError('lab configuration not found; copy '+EXAMPLE+' to lab.json beside the tools '
                      'or set '+ENVIRONMENT)


def load():
    global _loaded
    if _loaded is None:
        _loaded = json.loads(location().read_text(encoding='utf-8'))
    return _loaded


def lookup(data, key, allow_null=False):
    """Return a dotted key from parsed configuration or raise LookupError."""
    value = data
    for part in key.split('.'):
        if not isinstance(value, dict) or part not in value:
            raise LookupError('lab configuration key '+repr(key)+' is missing; set it in lab.json (see '+EXAMPLE+')')
        value = value[part]
    if value is None and not allow_null:
        raise LookupError('lab configuration key '+repr(key)+' is empty; set it in lab.json (see '+EXAMPLE+')')
    return value


def setting(key, allow_null=False):
    return lookup(load(), key, allow_null)


def mac(value, form='colon'):
    """Convert a configured MAC (hyphen, colon or bare hexadecimal form) to colon or VirtualBox form."""
    digits = ''.join(c for c in str(value) if c not in ':-').lower()
    if len(digits) != 12 or any(c not in '0123456789abcdef' for c in digits):
        raise ValueError('MAC address must have 12 hexadecimal digits')
    if form == 'vbox':
        return digits.upper()
    if form == 'colon':
        return ':'.join(digits[i:i+2] for i in range(0, 12, 2))
    raise ValueError('unknown MAC form')


def ps_quote(value):
    """Single-quoted PowerShell literal."""
    return "'"+str(value).replace("'", "''")+"'"


def fill(text, quote=repr, **values):
    """Replace @NAME@ placeholders in guest source text with quoted configured values."""
    for name, value in values.items():
        marker = '@'+name+'@'
        if marker not in text:
            raise KeyError('placeholder '+marker+' not present')
        text = text.replace(marker, quote(value))
    if '@' in text and any('@'+name+'@' in text for name in values):
        raise KeyError('placeholder left after fill')
    return text
