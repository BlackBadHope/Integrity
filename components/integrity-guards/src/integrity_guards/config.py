"""Shared configuration for the guards.

One JSON file holds every machine- or network-specific value. It is named by
``INTEGRITY_GUARDS_CONFIG``; without it every guard runs with neutral defaults
(no hosts, no device registry, no protected paths), which keeps each rule that
needs local knowledge inactive instead of guessing.

Sections: ``lock_guard``, ``rule_guard``, ``rules_drift``, ``uroboros``. See
``configuration.example.json`` next to this component's README.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ENV_CONFIG = "INTEGRITY_GUARDS_CONFIG"
ENV_STATE_ROOT = "INTEGRITY_GUARDS_STATE_ROOT"


def load(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Return the whole configuration, or {} when none is configured or it is unreadable.

    Hooks must never break a tool call, so a broken file reads as "not configured".
    """
    source = path or os.environ.get(ENV_CONFIG)
    if not source:
        return {}
    try:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def section(name: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    data = load() if config is None else config
    value = data.get(name)
    return value if isinstance(value, dict) else {}


def state_root() -> Path:
    """Per-user directory for guard caches and counters."""
    env = os.environ.get(ENV_STATE_ROOT)
    if env:
        return Path(env)
    try:
        return Path.home() / ".integrity-guards"
    except RuntimeError:  # no home in a stripped environment
        return Path(os.environ.get("TEMP") or os.environ.get("TMPDIR") or ".") / "integrity-guards"
