#!/usr/bin/env bash
# Install script for a Codex cloud environment of this repository.
#
# Paste it into the environment's "Install script" field. It runs once, while the
# environment is prepared, and the prepared filesystem is reused by later tasks.
# It therefore installs software only. It creates no signing key, journal or
# credential: each task makes its own key with `integrity-cloud open`.
#
# It needs package-registry access during setup and nothing else. It adds no
# secret, token, address or remote Integrity endpoint.
set -euo pipefail

python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
python -m pip install ./components/integrity-home
# setuptools lets examples/cloud-agents/ensure-integrity-cloud.sh reinstall the
# component offline when a task's branch is newer than this prepared filesystem.
python -m pip install "build>=1.2,<2" "packaging>=24,<27" "pytest>=8.2,<10" "setuptools>=77"

# Put the venv on PATH for the agent phase, set INTEGRITY_CLOUD=1 (the switch
# that AGENTS.md checks), install optional observation hooks into
# ~/.codex/hooks.json and run an offline self-test. No key is created here.
if [ -d components/integrity-cloud ]; then
  python -m pip install ./components/integrity-cloud
  integrity-cloud bootstrap
else
  echo "integrity-cloud is not on this branch; a task on a newer branch installs it offline"
fi
