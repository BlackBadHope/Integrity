# integrity-experience-adapters

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

A set of optional building blocks for user-facing features around an Integrity agent: offline
JSON contracts (work plans, transcripts, memory estimates, inert HTML previews) and host-side
backends for local speech, a stdio MCP client, a realtime voice broker and Git release
inventories. It is for host developers; nothing here runs unless a host calls it.

## Status

- Version `0.1.0rc3`, a release candidate.
- Python 3.11 or newer. No runtime dependencies for the contracts and the CLI.
- Optional extras with pinned direct packages (not full transitive locks): `images`
  (`Pillow==12.3.0`), `asr` (`faster-whisper==1.2.1`), `browser-tests` (`Pillow==12.3.0`,
  `playwright==1.57.0`).
- `GuardianDispatch` needs `integrity-adapter-sdk` at run time (it pins
  `integrity-guardian==7.0.0`); without it, it refuses with `exact_guardian_sdk_unavailable`.
  The SDK is not a declared dependency.
- The wheel includes `static/voice.mjs`, a browser client for the voice broker.

## What it does

**Offline contracts** (`contracts.py`). Each returns an unsigned `candidate` document with
`execution_authority: false` and a payload SHA-256. JSON input is capped at 256 KiB.

| Function | Behaviour |
| --- | --- |
| `capabilities()` | Static description of the offline API and the optional host modules. |
| `compare_contract(expected, actual)` | Typed JSON equality of two documents. |
| `validate_workplan(plan)` | Exactly six roles (`contract`, `baseline`, `migration_a`, `migration_b`, `verification`, `docs`), no overlapping write paths, and a verifier who is not also another role. |
| `transcript_observation(report)` | Checks the shape of a transcript report (audio hash, duration, model identity, ordered segments) and marks it as an unverified backend report. |
| `estimate_memory(spec)` | Weight plus KV-cache bytes for a dense decoder. Arithmetic only; `measured` is false. |
| `inert_preview(source)` | Static HTML preview: attributes removed, active or unknown markup escaped. |
| `validate_mcp`, `realtime_request`, `select_tts`, `validate_companion`, `release_inventory` | Shape and bound checks for the host backends below. |

**Host backends** (call only from trusted host code):

| Module | Behaviour |
| --- | --- |
| `media.LocalWhisper` | Loads a hash-checked local faster-whisper model bundle and transcribes bounded PCM. |
| `media.synthesize_espeak` | Produces a WAV with a hash-checked eSpeak executable. |
| `media.decoded_companion` | Decodes and checks a companion sprite image with Pillow. |
| `mcp_client.StdioClient` | Starts a hash-checked stdio MCP server; `initialize`, `tools/list`, `tools/call` with protocol `2025-11-25`, frame and time limits, no retries. |
| `realtime.OpenAIWebRTC`, `realtime.VoiceBroker` | Server-side WebRTC SDP exchange with an explicitly passed key, and an authenticated WSGI endpoint with one-use request binding. |
| `release_tools.git_inventory`, `release_tools.audit_changed_paths` | Read and hash exact Git objects at a revision, ignoring the worktree; check changed paths against a work plan role. |
| `presentation.companion_page`, `presentation.preview_page` | Static pages for the sprite and the inert preview. |
| `sdk_bridge.GuardianDispatch` | Verifies an SDK execution envelope, consumes a genuine `AdapterDispatchPermit`, then calls one host-selected sink. |

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install ./components/integrity-experience-adapters
python -m pip install "./components/integrity-experience-adapters[images]"   # optional extra
```

## Use

The console script is `integrity-experience` (also `python -m integrity_experience_adapters`):

```bash
integrity-experience capabilities
integrity-experience memory-estimate spec.json
integrity-experience transcript report.json
integrity-experience workplan plan.json
integrity-experience preview candidate.html
integrity-experience parity expected.json actual.json
```

Output is one canonical JSON document. Exit codes: 0 for an accepted transform, 1 when
`parity` finds a difference, 2 for a rejected or unreadable input (also for wrong arguments).
Errors do not echo paths or input text. The CLI is offline; no exit code authorizes anything.

## What is verified

- Public CI builds this distribution as a wheel, checks the wheel contents and installs it
  together with all other distributions (`pip check`) on Ubuntu and Windows with Python 3.11
  and 3.12.
- There are no behaviour tests: the component has no `tests/` folder, and no test elsewhere in
  the repository imports it.

## What is not verified

- Every behaviour described above is read from the source code only.
- Speech recognition and speech synthesis with real models or voices.
- The voice broker with a real provider, microphone or browser peer.
- `voice.mjs` in a browser.
- `GuardianDispatch` with a real SDK permit.

## Limits

- The backends are sinks. Calling them directly from Python is not a permission system; do
  not expose them, or the broker's `bind`, on an unauthenticated endpoint.
- No backend downloads models, reads credentials from the environment or starts a server.
- The memory estimate is not a measurement or an allocation guarantee.
- The inert preview runs no scripts and is not an operating-system sandbox.

## License

Business Source License 1.1 (earlier releases Apache-2.0). See [LICENSE](LICENSE) and the
project [NOTICE](../../NOTICE). External packages, binaries and model weights are not bundled.
