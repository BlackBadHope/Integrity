"""integrity-cloud: signed turn journals for cloud agents without local hooks.

Inside the cloud task (agent side):
  open, turn-open, event, turn-close, seal, status, context, hook
Inside the cloud environment's install script:
  bootstrap (PATH line, optional hooks, offline self-test; creates no key)
On the trusted side:
  capsule build, verify, import-plan
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from . import capsule as capsule_mod
from .hooks import HOOK_EVENTS, install, run_hook
from .journal import EVENT_KINDS, NO_EVENT_REASONS, Journal, JournalError, default_home
from .verify import import_plan, load_bundle, load_seen, verify_bundle

BASHRC_BEGIN = "# >>> integrity-cloud >>>"
BASHRC_END = "# <<< integrity-cloud <<<"


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _journal(args) -> Journal:
    return Journal(Path(args.home) if args.home else None)


def cmd_open(args) -> int:
    capsule = None
    if args.capsule:
        capsule = capsule_mod.load(Path(args.capsule))
    elif os.environ.get("INTEGRITY_CLOUD_CAPSULE"):
        capsule = capsule_mod.load(Path(os.environ["INTEGRITY_CLOUD_CAPSULE"]))
    record = _journal(args).open(capsule=capsule, nonce=args.nonce, label=args.label,
                                 harness=args.harness)
    _print({"opened": record["journal_id"], "nonce": record["body"]["nonce"],
            "capsule_sha256": record["body"]["capsule_sha256"],
            "base_commit": record["body"]["base_commit"],
            "next": "integrity-cloud turn-open --intent '<what the user asked>'"})
    return 0


def cmd_turn_open(args) -> int:
    record = _journal(args).turn_open(args.intent)
    _print({"turn": record["body"]["turn"], "seq": record["seq"]})
    return 0


def cmd_event(args) -> int:
    details = json.loads(args.details_json) if args.details_json else None
    action = None
    if args.kind == "action" or any(v is not None for v in (args.target, args.command,
                                                              args.result, args.exit_code)):
        action = {"target": args.target, "command": args.command, "result": args.result,
                  "exit_code": args.exit_code}
    record = _journal(args).event(args.kind, args.summary, tags=args.tag, details=details,
                                  action=action)
    _print({"event_seq": record["seq"], "turn": record["body"]["turn"]})
    return 0


def cmd_turn_close(args) -> int:
    record = _journal(args).turn_close(args.outcome, reason=args.reason)
    _print({"closed_turn": record["body"]["turn"], "outcome": record["body"]["outcome"],
            "events": len(record["body"]["events"])})
    return 0


def cmd_seal(args) -> int:
    _print(_journal(args).seal(args.out))
    return 0


def cmd_status(args) -> int:
    state = _journal(args).state()
    state.pop("turn_events", None)
    _print(state)
    return 0


def cmd_context(args) -> int:
    path = Path(args.capsule) if args.capsule else _journal(args).home / "capsule.json"
    if not path.is_file():
        _print({"capsule": None, "note": "no read-only context capsule was provided"})
        return 0
    _print(capsule_mod.load(path))
    return 0


def cmd_hook(args) -> int:
    out, status = run_hook(args.event, sys.stdin.read(), _journal(args))
    if out:
        print(out)
    return status


def cmd_capsule_build(args) -> int:
    source = json.loads(Path(args.input).read_text(encoding="utf-8"))
    deny = ()
    if args.deny_file:
        deny = tuple(line.strip() for line in
                     Path(args.deny_file).read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.startswith("#"))
    built = capsule_mod.build(source, purpose=args.purpose, max_items=args.max_items,
                              max_bytes=args.max_bytes, deny_literals=deny)
    text = json.dumps(built, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        _print({"capsule": args.out, "sha256": built["sha256"], "nonce": built["nonce"],
                "items": len(built["items"])})
    else:
        sys.stdout.write(text)
    return 0


def _verify(args) -> tuple[dict, dict]:
    bundle = load_bundle(Path(args.bundle))
    report = verify_bundle(bundle, expect_nonce=args.expect_nonce,
                           expect_capsule=args.expect_capsule,
                           expect_base_commit=args.expect_base_commit,
                           seen=load_seen(Path(args.seen) if args.seen else None))
    return bundle, report


def _record_seen(args, report: dict) -> None:
    if args.seen and args.record_seen and report["verdict"] == "signed-chain-ok":
        with open(args.seen, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(report["journal_id"] + "\n")


def cmd_verify(args) -> int:
    _bundle, report = _verify(args)
    _record_seen(args, report)
    _print(report)
    return 0 if report["verdict"] == "signed-chain-ok" else 1


def cmd_import_plan(args) -> int:
    bundle, report = _verify(args)
    if report["verdict"] != "signed-chain-ok":
        _print(report)
        return 1
    plan = import_plan(bundle, report)
    _record_seen(args, report)
    text = json.dumps(plan, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        _print({"plan": args.out, "events": len(plan["events"]), "trust": "reported"})
    else:
        sys.stdout.write(text)
    return 0


def cmd_install_hooks(args) -> int:
    _print(install(Path(args.codex_home).expanduser(), python=args.python))
    return 0


def self_test() -> dict:
    with tempfile.TemporaryDirectory(prefix="integrity-cloud-selftest-") as tmp:
        journal = Journal(Path(tmp) / "home")
        journal.open(nonce="0" * 32, label="bootstrap self-test", base_commit="")
        journal.turn_open("self-test")
        journal.event("thought", "self-test event")
        journal.turn_close("events")
        sealed = journal.seal(Path(tmp) / "out" / "bundle.json")
        report = verify_bundle(load_bundle(Path(sealed["bundle"])), expect_nonce="0" * 32)
    return {"self_test": report["verdict"], "records": report["records"]}


def cmd_bootstrap(args) -> int:
    result = {"version": __version__, "python": sys.executable,
              "journal_home": str(default_home()), "key_created": False}
    if not args.no_bashrc:
        bashrc = Path(args.bashrc).expanduser()
        bin_dir = Path(sys.executable).parent
        block = "\n".join([BASHRC_BEGIN, "export INTEGRITY_CLOUD=1",
                           f'export PATH="{bin_dir}:$PATH"', BASHRC_END])
        text = bashrc.read_text(encoding="utf-8") if bashrc.is_file() else ""
        if BASHRC_BEGIN in text and BASHRC_END in text:
            head, rest = text.split(BASHRC_BEGIN, 1)
            text = head + block + rest.split(BASHRC_END, 1)[1]
        else:
            text = text + ("" if not text or text.endswith("\n") else "\n") + block + "\n"
        bashrc.write_text(text, encoding="utf-8", newline="\n")
        result["bashrc"] = str(bashrc)
    if not args.no_hooks:
        result["hooks"] = install(Path(args.codex_home).expanduser())
    result.update(self_test())
    _print(result)
    return 0 if result["self_test"] == "signed-chain-ok" else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="integrity-cloud", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--home", help="journal directory (default $INTEGRITY_CLOUD_HOME or "
                                  "~/.integrity-cloud); keep it outside the repository")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("open", help="start a journal with a fresh per-task signing key")
    s.add_argument("--capsule", help="read-only context capsule (or $INTEGRITY_CLOUD_CAPSULE)")
    s.add_argument("--nonce", help="launch nonce when no capsule is given")
    s.add_argument("--label", help="short task label")
    s.add_argument("--harness", default="codex-cloud")
    s.set_defaults(func=cmd_open)

    s = sub.add_parser("turn-open", help="open a turn for one user request")
    s.add_argument("--intent", required=True, help="the request in your own short words")
    s.set_defaults(func=cmd_turn_open)

    s = sub.add_parser("event", help="record a decision, result or external action")
    s.add_argument("--kind", required=True, choices=EVENT_KINDS)
    s.add_argument("--summary", required=True)
    s.add_argument("--tag", action="append")
    s.add_argument("--details-json")
    s.add_argument("--target", help="action: the system or path acted on")
    s.add_argument("--command", help="action: the command, without secrets")
    s.add_argument("--result", help="action: what happened")
    s.add_argument("--exit-code", type=int)
    s.set_defaults(func=cmd_event)

    s = sub.add_parser("turn-close", help="close the turn with a receipt")
    s.add_argument("--outcome", required=True, choices=("events", "no-event"))
    s.add_argument("--reason", choices=NO_EVENT_REASONS)
    s.set_defaults(func=cmd_turn_close)

    s = sub.add_parser("seal", help="seal, destroy the key and write the bundle")
    s.add_argument("--out", required=True, help="file or directory, e.g. integrity-journal/")
    s.set_defaults(func=cmd_seal)

    s = sub.add_parser("status", help="show the journal state")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("context", help="print the read-only context capsule")
    s.add_argument("--capsule")
    s.set_defaults(func=cmd_context)

    s = sub.add_parser("hook", help="Codex command-hook adapter (reads hook JSON on stdin)")
    s.add_argument("event", choices=HOOK_EVENTS)
    s.set_defaults(func=cmd_hook)

    s = sub.add_parser("capsule", help="trusted side: build a read-only context capsule")
    csub = s.add_subparsers(dest="capsule_command", required=True)
    b = csub.add_parser("build")
    b.add_argument("--input", required=True, help="JSON list of memory records")
    b.add_argument("--purpose", required=True)
    b.add_argument("--out")
    b.add_argument("--max-items", type=int, default=capsule_mod.DEFAULT_MAX_ITEMS)
    b.add_argument("--max-bytes", type=int, default=capsule_mod.DEFAULT_MAX_BYTES)
    b.add_argument("--deny-file", help="private literals (host names, domains) to refuse")
    b.set_defaults(func=cmd_capsule_build)

    for name, func, text in (("verify", cmd_verify, "trusted side: verify a sealed bundle"),
                             ("import-plan", cmd_import_plan,
                              "trusted side: verify, then print append drafts")):
        s = sub.add_parser(name, help=text)
        s.add_argument("bundle")
        s.add_argument("--expect-nonce")
        s.add_argument("--expect-capsule", help="sha256:... of the capsule you issued")
        s.add_argument("--expect-base-commit")
        s.add_argument("--seen", help="registry of imported journal ids (one per line)")
        s.add_argument("--record-seen", action="store_true",
                       help="append the journal id to --seen after a successful check")
        if name == "import-plan":
            s.add_argument("--out")
        s.set_defaults(func=func)

    s = sub.add_parser("install-hooks", help="merge optional observation hooks into hooks.json")
    s.add_argument("--codex-home", default="~/.codex")
    s.add_argument("--python")
    s.set_defaults(func=cmd_install_hooks)

    s = sub.add_parser("bootstrap", help="install-script step: PATH, hooks, self-test; no key")
    s.add_argument("--bashrc", default="~/.bashrc")
    s.add_argument("--codex-home", default="~/.codex")
    s.add_argument("--no-bashrc", action="store_true")
    s.add_argument("--no-hooks", action="store_true")
    s.set_defaults(func=cmd_bootstrap)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (JournalError, capsule_mod.CapsuleError, ValueError, OSError) as error:
        print(f"integrity-cloud: {error}", file=sys.stderr)
        return 2
