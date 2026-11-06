"""Offline verification of a sealed cloud journal and the import plan built from it.

``signed-chain-ok`` means: every record is signed by the key announced in the
first record, the hash chain and sequence are unbroken, turns are balanced,
every close lists exactly its turn's events, and the seal matches. It never
means the reported work happened. Imported events carry ``trust=reported``;
promotion to *verified* is a separate decision backed by evidence the agent did
not produce (the PR diff, logs of the target systems).
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__
from .journal import (BUNDLE_FORMAT, EVENT_KINDS, JOURNAL_FORMAT, MAX_BUNDLE_BYTES,
                      MAX_RECORDS, NO_EVENT_REASONS, RECORD_TYPES, record_hash,
                      signing_bytes, unb64)
from .scan import scan

PLAN_FORMAT = "integrity-cloud-import-plan/v1"
RECORD_KEYS = {"v", "journal_id", "seq", "prev", "ts_utc", "type", "body", "sig"}


def _parse_time(text: object) -> datetime | None:
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def load_bundle(path: Path) -> dict:
    data = Path(path).read_bytes()
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle is larger than {MAX_BUNDLE_BYTES} bytes")
    return json.loads(data.decode("utf-8"))


def load_seen(path: Path | None) -> set[str]:
    if path is None or not Path(path).is_file():
        return set()
    return {line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()}


def verify_bundle(bundle: dict, *, expect_nonce: str | None = None,
                  expect_capsule: str | None = None, expect_base_commit: str | None = None,
                  seen: set[str] | None = None) -> dict:
    rejects: list[str] = []
    warnings: list[str] = []
    report = {"verdict": "rejected", "trust": "reported", "journal_id": None,
              "public_key_sha256": None, "records": 0, "turns": 0, "events": 0,
              "observations": 0, "harness": None, "base_commit": None,
              "head": None, "rejects": rejects, "warnings": warnings,
              "verifier": {"name": "integrity-cloud", "version": __version__}}

    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT:
        rejects.append("bundle_format")
        return report
    records = bundle.get("records")
    if not isinstance(records, list) or not records:
        rejects.append("no_records")
        return report
    if len(records) > MAX_RECORDS:
        rejects.append("too_many_records")
        return report
    journal_id = bundle.get("journal_id")
    report["journal_id"] = journal_id
    report["records"] = len(records)
    if not isinstance(journal_id, str) or len(journal_id) != 32 or not all(
            c in "0123456789abcdef" for c in journal_id):
        rejects.append("journal_id_format")
        return report

    first = records[0]
    if not isinstance(first, dict) or first.get("type") != "open":
        rejects.append("first_record_not_open")
        return report
    open_body = first.get("body") if isinstance(first.get("body"), dict) else {}
    if open_body.get("format") != JOURNAL_FORMAT:
        rejects.append("journal_format")
    try:
        public_raw = unb64(open_body.get("public_key", ""))
        public = Ed25519PublicKey.from_public_bytes(public_raw)
    except (ValueError, TypeError):
        rejects.append("public_key_invalid")
        return report
    if bundle.get("public_key") != open_body.get("public_key"):
        rejects.append("bundle_public_key_mismatch")
    report["public_key_sha256"] = "sha256:" + hashlib.sha256(public_raw).hexdigest()
    report["harness"] = open_body.get("harness")
    report["base_commit"] = open_body.get("base_commit")

    prev = "genesis"
    last_time = None
    open_turn = None
    turn_counter = 0
    turn_events: list[str] = []
    counts = {"turns": 0, "events": 0, "observations": 0}
    sealed = False
    for index, record in enumerate(records):
        where = f"record[{index}]"
        if not isinstance(record, dict) or set(record) != RECORD_KEYS:
            rejects.append(f"{where}:record_shape")
            break
        if record["v"] != 1 or record["journal_id"] != journal_id:
            rejects.append(f"{where}:version_or_journal_id")
        if record["seq"] != index:
            rejects.append(f"{where}:sequence_gap")
        if record["prev"] != prev:
            rejects.append(f"{where}:chain_broken")
        try:
            public.verify(unb64(record["sig"]), signing_bytes(record))
        except (InvalidSignature, ValueError, TypeError):
            rejects.append(f"{where}:bad_signature")
        moment = _parse_time(record["ts_utc"])
        if moment is None:
            rejects.append(f"{where}:time_format")
        elif last_time is not None and moment < last_time:
            warnings.append(f"{where}:time_went_backwards")
        last_time = moment or last_time
        prev = record_hash(record)

        kind = record["type"]
        body = record["body"] if isinstance(record["body"], dict) else {}
        if kind not in RECORD_TYPES:
            rejects.append(f"{where}:unknown_type")
            continue
        if sealed:
            rejects.append(f"{where}:record_after_seal")
        if kind == "open":
            if index != 0:
                rejects.append(f"{where}:second_open")
        elif kind == "turn_open":
            if open_turn is not None:
                rejects.append(f"{where}:nested_turn")
            turn_counter += 1
            if body.get("turn") != turn_counter:
                rejects.append(f"{where}:turn_number")
            open_turn = body.get("turn")
            turn_events = []
        elif kind == "event":
            if open_turn is None or body.get("turn") != open_turn:
                rejects.append(f"{where}:event_outside_turn")
            if body.get("kind") not in EVENT_KINDS or not body.get("summary"):
                rejects.append(f"{where}:event_shape")
            if body.get("kind") == "action":
                action = body.get("action") or {}
                if not action.get("target") or not action.get("result"):
                    rejects.append(f"{where}:action_shape")
            counts["events"] += 1
            turn_events.append(prev)
        elif kind == "observation":
            counts["observations"] += 1
        elif kind == "turn_close":
            if open_turn is None or body.get("turn") != open_turn:
                rejects.append(f"{where}:close_without_turn")
            outcome = body.get("outcome")
            if body.get("events") != turn_events:
                rejects.append(f"{where}:receipt_events_mismatch")
            if outcome == "events":
                if not turn_events or body.get("no_event_reason") is not None:
                    rejects.append(f"{where}:receipt_outcome")
            elif outcome == "no-event":
                if turn_events or body.get("no_event_reason") not in NO_EVENT_REASONS:
                    rejects.append(f"{where}:receipt_outcome")
            else:
                rejects.append(f"{where}:receipt_outcome")
            counts["turns"] += 1
            open_turn = None
            turn_events = []
        elif kind == "seal":
            sealed = True
            if open_turn is not None:
                rejects.append(f"{where}:seal_with_open_turn")
            expected = {"records": index, **counts}
            if any(body.get(k) != v for k, v in expected.items()):
                rejects.append(f"{where}:seal_counts")
    if not sealed:
        rejects.append("unsealed")
    elif records[-1].get("type") != "seal":
        rejects.append("seal_not_last")

    for finding in scan(records):
        rejects.append(f"secret_like_content:{finding['finding']}")

    if expect_nonce is not None and open_body.get("nonce") != expect_nonce:
        rejects.append("nonce_mismatch")
    if expect_capsule is not None and open_body.get("capsule_sha256") != expect_capsule:
        rejects.append("capsule_mismatch")
    if expect_base_commit is not None and open_body.get("base_commit") != expect_base_commit:
        rejects.append("base_commit_mismatch")
    if seen and journal_id in seen:
        rejects.append("journal_already_imported")

    report.update(counts)
    report["head"] = prev
    if not rejects:
        report["verdict"] = "signed-chain-ok"
    return report


def import_plan(bundle: dict, report: dict, *, verified_utc: str | None = None) -> dict:
    """Event drafts for the ordinary client append path; never writes anything."""
    if report["verdict"] != "signed-chain-ok":
        raise ValueError("refusing to plan an import from a rejected journal")
    verified_utc = verified_utc or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    journal_id = report["journal_id"]
    base = {"source": "cloud-agent", "trust": "reported", "signature": "ephemeral-ed25519",
            "journal_id": journal_id, "public_key_sha256": report["public_key_sha256"],
            "harness": report["harness"], "base_commit": report["base_commit"],
            "journal_head": report["head"], "verified_by": report["verifier"],
            "verified_utc": verified_utc}
    events = []
    turns = []
    intents: dict[int, str] = {}
    for record in bundle["records"]:
        body = record["body"]
        if record["type"] == "turn_open":
            intents[body["turn"]] = body["intent"]
        elif record["type"] == "turn_close":
            turns.append({"turn": body["turn"], "intent": intents.get(body["turn"]),
                          "outcome": body["outcome"],
                          "no_event_reason": body["no_event_reason"],
                          "events": len(body["events"])})
        elif record["type"] == "event":
            kind = "task" if body["kind"] == "action" else body["kind"]
            tags = ["cloud-agent", "reported", *body.get("tags", [])]
            if body["kind"] == "action":
                tags.insert(2, "cloud-action")
            details = {"provenance": {**base, "seq": record["seq"], "ts_utc": record["ts_utc"],
                                      "record_sha256": record_hash(record),
                                      "turn": body["turn"],
                                      "turn_intent": intents.get(body["turn"])},
                       "reported_details": body.get("details", {})}
            if "action" in body:
                details["reported_action"] = body["action"]
            events.append({"event_uid": f"client:cloud-{journal_id}-{record['seq']}",
                           "kind": kind,
                           "summary": ("[cloud-agent, reported] " + body["summary"])[:2000],
                           "tags": list(dict.fromkeys(tags))[:20],
                           "details": details})
    summary = (f"[cloud-agent, reported] Cloud journal {journal_id} ({report['harness']}) "
               f"verified signed-chain-ok: {report['turns']} turns, {report['events']} events, "
               f"{report['observations']} hook observations. Content is the agent's own report; "
               "compare with the PR diff and target-system logs before treating it as verified.")
    events.insert(0, {"event_uid": f"client:cloud-{journal_id}-journal", "kind": "thought",
                      "summary": summary, "tags": ["cloud-agent", "reported", "cloud-journal"],
                      "details": {"provenance": base, "verification": report, "turns": turns}})
    return {"format": PLAN_FORMAT, "journal_id": journal_id, "trust": "reported",
            "events": events}
