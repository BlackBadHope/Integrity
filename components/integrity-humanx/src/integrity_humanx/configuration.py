"""Explicit owner configuration. Importing this module performs no I/O."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

COMPONENT = 'integrity-humanx'
ENVIRONMENT = 'INTEGRITY_HUMANX_CONFIG'
SCHEMA = "integrity/component-config/v1"
HUMAN_PREFIX = "human-"
ROOM_PREFIX = "room-"
_OPERATOR_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")   # no '_' or '%': the id is used inside SQL LIKE patterns

class ConfigurationError(ValueError):
    """The component has no complete owner configuration."""

def read_config(path=None):
    path = path or os.environ.get(ENVIRONMENT)
    if not path:
        raise ConfigurationError(COMPONENT + ": unconfigured; set " + ENVIRONMENT)
    source = Path(path)
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ConfigurationError(COMPONENT + ": configuration must be an absolute regular file")
    if source.stat().st_size > 1024 * 1024:
        raise ConfigurationError(COMPONENT + ": configuration exceeds size bound")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ConfigurationError(COMPONENT + ": invalid configuration JSON") from None
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ConfigurationError(COMPONENT + ": configuration schema mismatch")
    if document.get("component") != COMPONENT or document.get("configured") is not True:
        raise ConfigurationError(COMPONENT + ": unconfigured or component mismatch")
    values = document.get("values", {})
    if not isinstance(values, dict) or any(not isinstance(k, str) for k in values):
        raise ConfigurationError(COMPONENT + ": values must be an object")
    if document.get("guardian_version") != "6.1.0" or document.get("memory_api_version") != "2.11.0":
        raise ConfigurationError(COMPONENT + ": expected Guardian 6.1.0 / memory API 2.11.0")
    return document

def require_config(path=None):
    return read_config(path)

def value(name):
    values = read_config().get("values", {})
    result = values.get(name)
    if not isinstance(result, str) or not result.strip() or "\x00" in result:
        raise ConfigurationError(COMPONENT + ": own configuration value required: " + name)
    return result

def operator_id():
    """The configured operator id (no default). Lower-case letters, digits and '-' only."""
    result = value("operator_id")
    if not _OPERATOR_ID.fullmatch(result):
        raise ConfigurationError(COMPONENT + ": operator_id must match " + _OPERATOR_ID.pattern)
    return result

def operator_address():
    """Bus address of the operator: human-<operator_id> (llm-bus room_acl prefix)."""
    return HUMAN_PREFIX + operator_id()

def room_prefix():
    """Prefix of the room vendor addresses: room-<operator_id>-."""
    return ROOM_PREFIX + operator_id() + "-"

def room_address(vendor):
    """Bus address of one room vendor: room-<operator_id>-<vendor>."""
    return room_prefix() + str(vendor)
