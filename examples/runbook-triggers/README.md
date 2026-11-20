# Example runbook triggers

[Uroboros](../../docs/UROBOROS.md#event-triggered-turns) · [integrity-guards](../../components/integrity-guards/README.md#event-driven-runbooks)

`runbooks.json` is a dispatcher configuration with one trigger for each
source. Everything in it is invented: the log path, the unit names and both
routes in `compiled-routes/`. It stays `"enabled": false`.

| Trigger | Source | Route | What happens |
|---|---|---|---|
| `example.disk-full-log` | lines appended to a log file | `example.disk-usage-read` (read) | the route runs without a model |
| `example.disk-full-syslog` | a datagram on `127.0.0.1:5514` | `example.disk-usage-read` (read) | a headless `claude -p` turn is told to run the route |
| `example.unit-failed-journald` | journald, one unit (Linux) | `example.service-restart` (write) | a proposal: nothing is restarted |
| `example.monitor-webhook` | `POST /hook/example.monitor-webhook` on `127.0.0.1:8891` | `example.disk-usage-read` (read) | the route runs without a model |
| `example.hourly-root-check` | a timer, once an hour | `example.disk-usage-read` (read) | the route runs for `/` |

The disk trigger's regex has two named groups, `mount` and `percent`. The
route has one parameter, `mount`, so only that group becomes a parameter;
`percent` is only matched. A line such as
`filesystem /data;reboot is 99% full` does not match the trigger at all. If a
trigger's regex is looser than the route's (for example `(?P<mount>\S+)`),
the value is still checked with the route's own regex `/[a-z0-9/_-]{0,60}`
before anything starts, and the event is recorded as `rejected`.

## Try it without running anything

From a clone, with `integrity-guards` installed:

```bash
integrity-guards runbooks validate examples/runbook-triggers/runbooks.json
integrity-guards runbooks explain example.disk-full-log \
  --file examples/runbook-triggers/runbooks.json \
  --line "kernel: filesystem /data is 97% full"
integrity-guards runbooks explain example.unit-failed-journald \
  --file examples/runbook-triggers/runbooks.json \
  --line "example-app.service: Failed with result 'exit-code'."
```

`compiled_routes` is a relative path here, so run these from the root of the
clone. `explain` prints the decision (`turn`, `proposal` or `rejected`), the
parameters and the route command. It does not ask the kill switch, does not
apply the limits and runs nothing.

## Use it as a starting point

```bash
integrity-guards runbooks init --config examples/runbook-triggers/runbooks.json
```

Then edit the instance's `runbooks.json`:

- set `compiled_routes` to an absolute path of your own routes;
- keep only the triggers you want, with your own log paths and regexes;
- for `claude-p` or `codex-exec`, set the adapter's `cwd` to a project where
  Integrity admission and the guards are installed as hooks;
- for the webhook, export the token in the variable named by
  `listen.webhook_token_env` before the dispatcher starts;
- set `"enabled": true`, run `integrity-guards runbooks doctor`, then start
  the service ([integrity-guards](../../components/integrity-guards/README.md#event-driven-runbooks)).

To forward syslog to the dispatcher with rsyslog, a rule such as
`*.* @127.0.0.1:5514` sends every message as a UDP datagram; narrow the
selector to what your triggers need.
