# Contributing

Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/BlackBadHope/Integrity.git
cd Integrity
python -m venv ../integrity-venv  # outside the clone
. ../integrity-venv/bin/activate  # Windows PowerShell: ..\integrity-venv\Scripts\Activate.ps1
python -m pip install ".[dev]"
python -m pytest -q
```

Run Ruff for changed Python files:

```bash
python -m ruff check path/to/changed.py
```

The public surface check compares a tree with `PUBLIC-EXPORT-MANIFEST.json`
file by file, including file modes, so caches or a `.venv` inside your
checkout make it fail. Refresh the manifest for your change, commit, and check
a fresh clone of the commit, as CI does:

```bash
python .github/scripts/update_manifest.py            # refresh listed files
python .github/scripts/update_manifest.py --add path/to/new_module.py
git clone --quiet . ../surface-check
python .github/scripts/public_surface_check.py --root ../surface-check
```

New files are never picked up implicitly: name each one with `--add` (source)
or `--add-generated` (documentation, CI and packaging).

Keep changes focused and include tests for behavior changes. Do not weaken
signature, provenance, authority, deadline, cancellation or privacy checks to
make a test pass. Explain the problem, resulting behavior and validation in the
pull request.

The public repository is a closed projection of a larger canonical development
tree. Maintainers handle reconciliation; contributors need no private access.
Contributions require a signed [Contributor License Agreement](CLA.md). Add the
line it gives to your first pull request. The project is licensed under the
[Business Source License 1.1](LICENSE), and the licensor also offers
[commercial terms](COMMERCIAL.md); the CLA lets your contribution ship under both.

Report vulnerabilities through the private channel described in
[`SECURITY.md`](SECURITY.md).
