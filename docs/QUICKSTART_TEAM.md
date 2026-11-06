# Team quickstart (2–5 people)

Each person keeps their own model account. The shared core holds the Action
Log, Seed, bus, and work claims. Seats are access seats, not shared logins.

Install from a clean virtualenv using the
[public beta quickstart](../README.md#public-beta-quickstart): `python -m pip install .`
then `python -m pip install ./components/integrity-home`. `guardian version --all`
checks the Guardian install. The commands below use `integrity-seats` from
`integrity-home`.

## New core

On the machine that will host the core, from the repository root with the
virtualenv activated:

```bash
python -m pip install .
python -m pip install ./components/integrity-home
integrity-seats --registry /absolute/path/seat-registry.sqlite3 --isolation-mode shared-core init --root /absolute/path/core
integrity-seats --registry /absolute/path/seat-registry.sqlite3 seat create --seat-id seat_owner --display-name Owner --role go_approver --role admin --namespace 'team/*' --namespace 'seat/seat_owner/*'
```

`integrity-seats` is the console script from the `integrity-home` package.
`python -m pip install .` at the repository root installs Guardian only and
does not install that package. Global options (`--registry`,
`--isolation-mode`) belong before the subcommand. `init` takes `--root`.

Create one seat per person (`alice`, `bob`, …) with only the roles they need.
Issue a token into a mode `0600` file and give that file only to that person.

Linux, macOS, and Windows can run the same commands. On Windows, protect the
token file with a user-only ACL. The core URL in docs is `<CORE_HOST>`.
Use `example.invalid` in examples. Do not publish a live tunnel port.

Existing single-user or silo installs stay as they are until
`integrity-seats migrate from-single-host`. See
[MIGRATION_INTEGRITY_SEATS.md](MIGRATION_INTEGRITY_SEATS.md).

Mode A (OAuth gateway) is the path for a team. Mode B (personal tunnel) is
optional. Confirm the current OpenAI docs before using a tunnel.
