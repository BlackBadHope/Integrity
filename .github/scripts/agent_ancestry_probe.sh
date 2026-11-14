#!/usr/bin/env bash
# Records how the kill switch classifies whoever runs this script.
#
# Used by .github/workflows/real-claude.yml: once without an agent (control)
# and from a real Claude Code session. The file name names no vendor on
# purpose, so a match can only come from the processes above it.
set -u
unset ANTHROPIC_API_KEY
out="${PROBE_OUT:?}/${PROBE_LABEL:?}.txt"
ks="${PROBE_KS:?}"
{
  echo "run=1"
  "$ks" doctor --json > "$PROBE_OUT/$PROBE_LABEL-doctor.json"
  echo "doctor_exit=$?"
  "$ks" check --action probe
  echo "check_before_exit=$?"
  "$ks" off claude --reason probe > /dev/null
  echo "off_exit=$?"
  "$ks" check --action probe
  echo "check_after_exit=$?"
  "$ks" on claude --reason probe > /dev/null
  echo "on_exit=$?"
  chain=""
  pid=$$
  while [ -n "$pid" ] && [ "$pid" -gt 1 ]; do
    chain="$chain $(cat "/proc/$pid/comm" 2>/dev/null || echo '?')"
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
  done
  echo "chain=$chain"
} >> "$out" 2>&1
echo "probe recorded"
