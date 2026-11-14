#!/usr/bin/env python3
"""Check what the real Claude Code workflow recorded and report its cost.

Reads the probe records and the two `claude -p --output-format json` results
from PROBE_OUT. Prints only exit codes, process names, the caller line of the
kill switch doctor, token counts and the cost estimate Claude Code reports;
never the model's reply text. Exits 1 when an expectation fails.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

OUT = Path(os.environ["PROBE_OUT"])


def records(label: str) -> list[dict[str, str]]:
    path = OUT / f"{label}.txt"
    runs: list[dict[str, str]] = []
    if not path.is_file():
        return runs
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if not sep or not key.replace("_", "").isalnum():
            continue
        if key == "run":
            runs.append({})
        elif runs:
            runs[-1][key] = value.strip()
    return runs


def caller(label: str) -> str:
    path = OUT / f"{label}-doctor.json"
    if not path.is_file():
        return "missing"
    report = json.loads(path.read_text(encoding="utf-8"))
    return next((c["detail"] for c in report.get("checks", []) if c.get("check") == "caller"), "missing")


def usage(name: str) -> dict[str, object]:
    path = OUT / f"{name}.json"
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"run": name, "models": "no JSON result"}
    tokens = result.get("usage") or {}
    return {
        "run": name,
        "models": ",".join(sorted((result.get("modelUsage") or {}).keys())) or "unknown",
        "turns": result.get("num_turns"),
        "is_error": result.get("is_error"),
        "input_tokens": tokens.get("input_tokens"),
        "cache_creation_input_tokens": tokens.get("cache_creation_input_tokens"),
        "cache_read_input_tokens": tokens.get("cache_read_input_tokens"),
        "output_tokens": tokens.get("output_tokens"),
        "cost_usd_estimate": result.get("total_cost_usd"),
    }


def main() -> int:
    failures = []
    control, agent = records("control"), records("agent")
    control_caller, agent_caller = caller("control"), caller("agent")

    if len(control) != 1:
        failures.append(f"control probe ran {len(control)} times, expected 1")
    if "detected as claude" in control_caller:
        failures.append("control probe without an agent was classified as claude")
    if len(agent) != 1:
        failures.append(f"probe under Claude Code ran {len(agent)} times, expected 1 "
                        "(once with the switch on, never after it was turned off)")
    if "detected as claude" not in agent_caller:
        failures.append("probe under Claude Code was not classified as claude")
    if agent:
        first = agent[0]
        for key, expected in (("check_before_exit", "0"), ("off_exit", "0"), ("check_after_exit", "3")):
            if first.get(key) != expected:
                failures.append(f"under Claude Code {key}={first.get(key)}, expected {expected}")
        if first.get("on_exit") in (None, "0"):
            failures.append(f"under Claude Code on_exit={first.get('on_exit')}, expected a refusal")

    lines = ["## Real Claude Code client", "",
             f"- control caller: {control_caller}",
             f"- control ancestry:{(control[0].get('chain', '') if control else ' none')}",
             f"- Claude Code caller: {agent_caller}",
             f"- Claude Code ancestry:{(agent[0].get('chain', '') if agent else ' none')}",
             f"- Claude Code exit codes: " + (", ".join(f"{k}={v}" for k, v in agent[0].items() if k.endswith("_exit"))
                                             if agent else "none"),
             "", "| run | models | turns | error | input | cache write | cache read | output | cost USD (Claude Code estimate) |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for name in ("switch-on", "switch-off"):
        u = usage(name)
        lines.append("| " + " | ".join(str(u.get(k, "")) for k in (
            "run", "models", "turns", "is_error", "input_tokens", "cache_creation_input_tokens",
            "cache_read_input_tokens", "output_tokens", "cost_usd_estimate")) + " |")
    lines += ["", "Result: " + ("PASS" if not failures else "FAIL")] + [f"- {f}" for f in failures]
    text = "\n".join(lines) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
