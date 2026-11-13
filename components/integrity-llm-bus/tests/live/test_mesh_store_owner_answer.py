"""A work node blocked on a decision opens only on the owner's approval of exactly that decision.

Every case runs against an in-memory bus table with synthetic agents. The
projection under test is ``resources/mesh_store.py``.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

import mesh_store as ms
import mesh_validate as mv

LEAD, WORKER, OTHER = "lead", "worker", "helper"
LIMITS = dict(ms.DEFAULT_LIMITS, pm=LEAD)
SHA = "ab12" * 16
FOREIGN_SHA = "cd34" * 16
REF = SHA[:16]
NODE_A, NODE_B = "W-example-a", "W-example-b"


class Bus:
    """The part of the bus table the projection reads, with a clock that moves one second per message."""

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,"
                        " sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL, reply_to TEXT,"
                        " created_at INTEGER NOT NULL)")
        ms.ensure_schema(self.db)
        self.clock = 1_000_000

    def post(self, msg_id, sender, recipient, body, reply_to=None) -> str:
        self.clock += 1
        self.db.execute("INSERT INTO messages(id, sender, recipient, body, reply_to, created_at) VALUES(?,?,?,?,?,?)",
                        (msg_id, sender, recipient, json.dumps(body), reply_to, self.clock))
        ms.project(self.db, LIMITS)
        return ms.outcome(self.db, msg_id)

    def mesh(self, msg_id, sender, recipient, kind, work, **extra) -> str:
        body = {"v": 1, "k": "status", "th": work, "need": "none",
                "data": {"mesh": {"p": mv.PROTOCOL, "kind": kind, "work": work, **extra}}}
        return self.post(msg_id, sender, recipient, body)

    def state(self, work):
        return self.db.execute("SELECT state, block_reason FROM mesh_work WHERE work=?", (work,)).fetchone()

    def expire(self, msg_id):
        self.db.execute("DELETE FROM messages WHERE id=?", (msg_id,))


def ask(bus, msg_id, sender=LEAD, *, k="question", need="answer", **data):
    return bus.post(msg_id, sender, mv.OWNER, {"v": 1, "k": k, "need": need, "data": data})


def answer(bus, msg_id, *, to=LEAD, reply_to="ask-a", disposition="approve", text=f"approved {REF}", k="decision",
           **data):
    body = {"v": 1, "k": k, "need": "none", "data": {"disposition": disposition, "text": text, **data}}
    return bus.post(msg_id, mv.OWNER, to, body, reply_to)


def progress(bus, msg_id, work, cite=None) -> str:
    extra = {"cite": {"owner": cite}} if cite else {}
    return bus.mesh(msg_id, WORKER, LEAD, "progress", work, **extra)


@pytest.fixture
def bus():
    """Two nodes opened under one owner charter, both claimed and both blocked on the same decision text."""
    bus = Bus()
    bus.post("charter", mv.OWNER, LEAD, {"v": 1, "k": "decision", "need": "none", "data": {"text": "do the work"}})
    ask(bus, "ask-early", work=NODE_A, decision_ref=REF)  # posted before the decision-request exists
    request = {"text": "apply the change", "impact": "one service", "rollback": "restore the copy", "sha256": SHA}
    for work in (NODE_A, NODE_B):
        tag = work[-1]
        assert bus.mesh(f"open-{tag}", LEAD, WORKER, "open", work, cite={"owner": "charter"}) == "accepted"
        assert bus.mesh(f"claim-{tag}", WORKER, LEAD, "claim", work, claim={"expect": 0, "lease_s": 600}) == "accepted"
        assert bus.mesh(f"request-{tag}", WORKER, LEAD, "decision-request", work, body=request) == "accepted"
        assert bus.state(work) == ("blocked", "decision")
    ask(bus, "ask-a", work=NODE_A, decision_ref=REF)
    ask(bus, "ask-b", work=NODE_B, decision_ref=REF)
    ask(bus, "ask-worker", WORKER, work=NODE_A, decision_ref=REF)
    ask(bus, "ask-unrelated", topic="something else")
    ask(bus, "ask-foreign", work=NODE_A, decision_ref=FOREIGN_SHA[:16])
    ask(bus, "ask-fyi", k="fyi", need="none", work=NODE_A, decision_ref=REF)
    ask(bus, "ask-no-work", decision_ref=REF)
    return bus


NOT_AN_ANSWER = "rejected:cite-not-decision-answer"

REFUSED = {
    "reject": {"disposition": "reject"},
    "defer": {"disposition": "defer"},
    "a question, not a decision": {"k": "question"},
    "approval sent to another agent": {"to": OTHER},
    "approval without the reference": {"text": "approved"},
    "approval that answers nothing": {"reply_to": None},
    "approval of an unrelated question": {"reply_to": "ask-unrelated"},
    "approval of a question about another decision": {"reply_to": "ask-foreign"},
    "reference outside the text": {"text": "approved", "decision_ref": REF, "note": REF},
    "approval of a question older than the request": {"reply_to": "ask-early"},
    "approval of a notice that asked nothing": {"reply_to": "ask-fyi"},
    "approval of a question that names no node": {"reply_to": "ask-no-work"},
    "approval of the question about the twin node": {"reply_to": "ask-b"},
    "approval to the worker of the lead's question": {"to": WORKER},
    "reference shorter than the minimum": {"text": f"approved {SHA[:ms.DECISION_REF - 1]}"},
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_other_owner_messages_do_not_unblock(bus, case):
    answer(bus, "owner-says", **REFUSED[case])
    assert progress(bus, "go", NODE_A, cite="owner-says") == NOT_AN_ANSWER
    assert bus.state(NODE_A) == ("blocked", "decision")


def test_progress_without_a_cite_is_refused(bus):
    answer(bus, "owner-says")
    assert progress(bus, "go", NODE_A) == "rejected:needs-owner-cite"


def test_the_charter_is_not_an_answer(bus):
    assert progress(bus, "go", NODE_A, cite="charter") == NOT_AN_ANSWER


def test_a_cite_of_an_unknown_message_is_refused(bus):
    assert progress(bus, "go", NODE_A, cite="no-such-message") == "rejected:unknown-cite"


def test_approval_of_the_leads_question_unblocks_that_node_only(bus):
    answer(bus, "owner-says")
    assert progress(bus, "go-b", NODE_B, cite="owner-says") == NOT_AN_ANSWER
    assert progress(bus, "go-a", NODE_A, cite="owner-says") == "accepted"
    assert bus.state(NODE_A) == ("claimed", None)
    assert bus.state(NODE_B) == ("blocked", "decision")
    assert bus.db.execute("SELECT unblock FROM mesh_msgs WHERE msg='go-a'").fetchone() == (1,)
    answer(bus, "owner-says-b", reply_to="ask-b")
    assert progress(bus, "go-b-again", NODE_B, cite="owner-says-b") == "accepted"
    assert bus.state(NODE_B) == ("claimed", None)


def test_approval_of_the_workers_own_question_unblocks(bus):
    answer(bus, "owner-says", to=WORKER, reply_to="ask-worker")
    assert progress(bus, "go", NODE_A, cite="owner-says") == "accepted"


def test_only_the_claimant_may_use_the_answer(bus):
    answer(bus, "owner-says")
    outcome = bus.mesh("go", OTHER, LEAD, "progress", NODE_A, cite={"owner": "owner-says"})
    assert outcome == "rejected:not-claimant"


def test_rebuild_agrees_with_the_projection(bus):
    answer(bus, "owner-no", disposition="reject")
    assert progress(bus, "go-refused", NODE_A, cite="owner-no") == NOT_AN_ANSWER
    answer(bus, "owner-says")
    assert progress(bus, "go", NODE_A, cite="owner-says") == "accepted"
    report = ms.rebuild(bus.db, LIMITS)
    assert report["diffs"] == [] and report["applied"] is False


@pytest.mark.parametrize("expired", ["owner-says", "ask-a"])
def test_recorded_unblock_survives_expiry_of_the_chain(bus, expired):
    answer(bus, "owner-says")
    assert progress(bus, "go", NODE_A, cite="owner-says") == "accepted"
    bus.expire(expired)
    assert ms.rebuild(bus.db, LIMITS)["diffs"] == []


def test_rebuild_does_not_keep_an_unblock_the_live_chain_refutes(bus):
    answer(bus, "owner-no", disposition="reject")
    assert progress(bus, "go", NODE_A, cite="owner-no") == NOT_AN_ANSWER
    # A forged record of an accepted unblock: the refusal and its question are still on the bus, so replay decides.
    bus.db.execute("DELETE FROM mesh_rejects WHERE msg='go'")
    bus.db.execute("INSERT INTO mesh_msgs(msg, seq, work, kind, sender, created_at, bytes, cite, unblock)"
                   " VALUES('go', 999, ?, 'progress', ?, ?, 1, 'owner-no', 1)", (NODE_A, WORKER, bus.clock))
    bus.db.execute("UPDATE mesh_work SET state='claimed', block_reason=NULL WHERE work=?", (NODE_A,))
    report = ms.rebuild(bus.db, LIMITS)
    assert [diff["work"] for diff in report["diffs"]] == [NODE_A]
    assert report["diffs"][0]["rebuilt"][1] == "blocked"


def test_a_message_from_the_coordinator_is_never_an_owner_answer(bus):
    body = {"v": 1, "k": "decision", "need": "none", "data": {"disposition": "approve", "text": f"approved {REF}"}}
    bus.post("lead-says", LEAD, WORKER, body, "ask-worker")
    assert progress(bus, "go", NODE_A, cite="lead-says") == "rejected:unknown-cite"
    assert bus.state(NODE_A) == ("blocked", "decision")


def test_the_owner_is_never_a_party_of_a_mesh_message(bus):
    assert bus.mesh("from-owner", mv.OWNER, WORKER, "open", "W-example-c").startswith("rejected:invalid:the owner")
    assert bus.mesh("to-owner", LEAD, mv.OWNER, "open", "W-example-d").startswith("rejected:invalid:the owner")


def test_the_coordinator_may_cancel_a_node_it_did_not_open(bus):
    assert bus.mesh("open-c", OTHER, WORKER, "open", "W-example-c") == "accepted"
    assert bus.mesh("cancel-by-worker", WORKER, OTHER, "cancel", "W-example-c") == "rejected:not-allowed"
    assert bus.mesh("cancel-by-lead", LEAD, OTHER, "cancel", "W-example-c") == "accepted"
    assert bus.state("W-example-c") == ("cancelled", None)


def test_the_coordinator_address_comes_from_the_limits_file(tmp_path):
    assert ms.load_limits(tmp_path)["pm"] == ms.DEFAULT_LIMITS["pm"]
    (tmp_path / "mesh-limits.json").write_text(json.dumps({"pm": LEAD, "open_claims": 2}), encoding="utf-8")
    limits = ms.load_limits(tmp_path)
    assert limits["pm"] == LEAD and limits["open_claims"] == 2
    (tmp_path / "mesh-limits.json").write_text(json.dumps({"pm": mv.OWNER}), encoding="utf-8")
    assert ms.load_limits(tmp_path)["pm"] == ms.DEFAULT_LIMITS["pm"]
