# Install and test

[Documentation](README.md) · [Project README](../README.md)

This page installs Integrity from source and runs the same checks as public
CI. It does not create an instance: for that, continue with the
[clean bootstrap](../BOOTSTRAP.md).

## Prerequisites

- Git and Python 3.11 or newer. CI runs 3.11 and 3.12 on Linux and Windows.
  macOS is not supported yet (see [what is verified](STATUS.md#platform-support)).
- Node.js 18+ with npm is optional and only needed for the `integrity-space`
  UI tests.
- Debian and Ubuntu ship `python3` without a `python` alias and without venv
  or pip. Install them first, then create the virtualenv with `python3`:

  ```bash
  sudo apt install git python3 python3-venv python3-pip bubblewrap
  ```

  `bubblewrap` is the Linux sandbox the test suite uses. Inside an activated
  virtualenv, `python` works on every platform.
- Create the virtualenv **outside** the clone, as the commands below do
  (`../integrity-venv`). The public surface check scans the whole tree and
  fails on a `.venv` inside it.

## Install from source

```bash
git clone https://github.com/BlackBadHope/Integrity.git
cd Integrity
python -m venv ../integrity-venv
```

To build the stable release instead of current `main`, run
`git checkout v7.0.1` after `cd Integrity`. To roll back, check out `v7.0.0`,
and keep your existing install until the new one passes your checks.

Activate the environment:

```bash
# Linux
. ../integrity-venv/bin/activate

# Windows PowerShell
..\integrity-venv\Scripts\Activate.ps1
```

Install Guardian and inspect the local profile:

```bash
python -m pip install --upgrade pip
python -m pip install .
guardian version --all
guardian capabilities
guardian lts-contracts
```

`guardian version --all` reports the public source profile for version 7.0.0.
These commands do not enroll a host or grant action authority.

### The seats console

`integrity-seats`, used by the [team quickstart](QUICKSTART_TEAM.md), comes
from the `integrity-home` component:

```bash
python -m pip install ./components/integrity-home
```

Global options belong before the subcommand.

### The kill switch alone

`integrity-killswitch` needs nothing else from this repository, not even
Guardian. Its [README](../components/integrity-killswitch/README.md#install-it-on-its-own)
gives the install command, the `doctor` check and the removal.

### Other components

[BOOTSTRAP.md](../BOOTSTRAP.md#install-functional-components) shows how to
install the optional components. The
[component table](../README.md#components) lists them all.

## Run the test suite

Public CI (`.github/workflows/public-surface.yml`) runs these checks on Ubuntu
and Windows with Python 3.11 and 3.12, plus an informational macOS job. Linux
CI also installs `bubblewrap`.

Reproduce them from the root of a **clean clone**. A source install
(`pip install .` or `./components/...`) leaves `*.egg-info` build files that
the surface check rejects, so check a fresh `git clone` of your commit, as CI
does. Use a new disposable directory for build output; the examples use
`$TMPDIR` or `/tmp` and do not read retained state.

The quickstart does not install pytest or the components. Running pytest
straight after it fails with `No module named pytest`.

```bash
python -m pip install "build>=1.2,<2" "packaging>=24,<27" "pytest>=8.2,<10"
python .github/scripts/public_surface_check.py --root .
python .github/scripts/component_catalog.py --root .
python components/integrity-installed-runtime/verify_sources.py
python -B components/integrity-seed/verify_public_surface.py
OUT="${TMPDIR:-/tmp}/integrity-dist"
python .github/scripts/build_components.py --root . --output "$OUT"
python .github/scripts/verify_wheels.py --root . --wheels "$OUT"
python .github/scripts/install_components.py --wheels "$OUT" --venv "${TMPDIR:-/tmp}/integrity-check"
```

Activate that virtual environment. CI appends its `bin` directory to `PATH`
instead. You do not need to `deactivate` the first venv, because activating
another one replaces it.

```bash
. "${TMPDIR:-/tmp}/integrity-check/bin/activate"            # Linux
# . "${TMPDIR:-/tmp}/integrity-check/Scripts/activate"      # Windows, Git Bash
```

Then run the installed profile, the public tests, the local MCP walkthrough
and the component tests:

```bash
guardian version --all
guardian capabilities
guardian lts-contracts
python -B -m pytest -q -p no:cacheprovider
CASE="${TMPDIR:-/tmp}/local-memory-case"
CLIENTS="${TMPDIR:-/tmp}/local-memory-clients"
python -B examples/local-memory/create_case.py --output "$CASE"
python -B examples/local-memory/setup.py --catalog "$CASE/private/catalog.sqlite" --output "$CLIENTS"
python -B examples/local-memory/verify_connection.py "$CLIENTS/codex.config.toml" "$CLIENTS/claude.mcp.json" "$CLIENTS/antigravity.mcp.json"
python -B -m pytest -q -p no:cacheprovider --import-mode=importlib components/*/tests
```

From `components/integrity-space`, run `npm test` for the shipped UI models.
Root pytest includes `tests/hygiene/test_public_export_hygiene.py`.

### Reading the result

A full run skips some tests on every platform.
[Expected test skips](expected-test-skips.md) lists them per platform,
measured in CI, so you can tell a normal run from a broken one.

On Linux the Native client-memory profiles run rather than skip. Linux CI
fails on any client-memory skip outside the reviewed list
(`.github/scripts/native_skip_guard.py`); skips in other suites are not
guarded. See [Linux native clients](linux-native-clients.md).

These checks verify the closed export manifest, component metadata, the
canonical source layout, package builds and dependency compatibility, CLI
smoke commands and synthetic functional tests. See
[what the public suite verifies](../ARCHITECTURE.md#what-the-public-suite-verifies).

## The diagrams

The pictures in the documentation are generated. To change one, edit
`docs/assets/build_assets.py`, run it, and commit both the light and the dark
variant:

```bash
python docs/assets/build_assets.py
python docs/assets/build_assets.py --check
```
