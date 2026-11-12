# SPDX-License-Identifier: BUSL-1.1
"""Generic SessionStart / turn hook: make this thread addressable. Prints nothing, always exit 0.

Usage in hook config: python autoreg_hook.py --harness claude|codex|antigravity
Identity: payload session_id / thread_id / conversationId. Never reads or stores prompt text.
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import json
import sys
from pathlib import Path

import autoreg


def identity_of(payload: dict):
    for key in ("session_id", "thread_id", "conversationId"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return None


def main(argv=None) -> int:
    try:
        argv = sys.argv[1:] if argv is None else argv
        harness = argv[argv.index("--harness") + 1] if "--harness" in argv else "claude"
        raw = sys.stdin.buffer.read(512 * 1024 + 1)
        payload = json.loads(raw) if raw and len(raw) <= 512 * 1024 else {}
        if not isinstance(payload, dict):
            return 0
        ident = identity_of(payload)
        if ident:
            cwd = payload.get("cwd")
            autoreg.ensure_bounded(harness, ident, source="hook:" + str(payload.get("hook_event_name", "?"))[:24],
                                   model=payload.get("modelName"),
                                   topic=(f"{Path(cwd).name} {harness}" if isinstance(cwd, str) else harness)[:200])
    except Exception:
        pass
    return 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
