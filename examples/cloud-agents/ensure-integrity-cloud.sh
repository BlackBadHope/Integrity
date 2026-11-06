#!/usr/bin/env bash
# Install integrity-cloud from this checkout without network access.
#
# A cloud environment's prepared filesystem can predate the checked-out branch
# (for example a task started on a branch that adds or changes the component).
# The install script already placed setuptools and cryptography in .venv, so the
# component installs offline. Hooks installed now take effect from the next
# session; the journal itself works immediately.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
python="$root/.venv/bin/python"
[ -x "$python" ] || python="$(command -v python3)"

"$python" -m pip install --quiet --no-index --no-build-isolation --no-deps \
  "$root/components/integrity-cloud"
"$python" -m integrity_cloud bootstrap
echo "integrity-cloud ready: run '. ~/.bashrc' or call $(dirname "$python")/integrity-cloud"
