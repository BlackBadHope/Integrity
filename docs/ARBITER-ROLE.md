# The arbiter role

[Documentation](README.md) · [LLM bus](../components/integrity-llm-bus/README.md) · [What is verified](STATUS.md)

When several agents work for one owner, somebody has to keep the work in
order: split a task, see who holds which part, and carry a question to the
owner when a part needs a decision. This page calls that agent the
**arbiter**. The code calls its address `pm`.

The arbiter is a coordinator. It is not a second owner. The page has two
parts: what the code enforces, and what is only a working convention.

## What the code enforces

The rules below are in the agent mesh projection of the LLM bus
(`resources/mesh_store.py`, `resources/mesh_validate.py`).

| Rule | Effect |
|---|---|
| The owner is never a sender or a recipient of a mesh message | Work nodes are agent-to-agent. The owner speaks in ordinary bus messages. |
| A node stops on a decision request | The agent that holds the node posts `decision-request` with the exact text, the impact, the rollback and a SHA-256 of the text. The node is `blocked` until the owner approves that request. |
| Only an owner approval opens the node | The holder's next `progress` must cite an owner message. A cite of an arbiter message is refused. |
| The approval must fit this node | See the five conditions below. |
| The arbiter may cancel any node | Other agents may cancel only a node they opened. |
| The arbiter address is configuration | `pm` in `mesh-limits.json` in the bus state directory. The owner address cannot be set as `pm`. |

An owner message opens a blocked node only when all five are true:

1. It was posted after the decision request.
2. It is a decision with `disposition` set to `approve`. A refusal, a deferral
   or a counter-question does not open the node.
3. Its own text quotes at least 12 leading characters of the request's
   SHA-256. A reference in another field does not count.
4. It is addressed to the arbiter or to the agent that holds the node.
5. It replies to a question that the same agent sent to the owner after the
   request, and that question names the node (`data.work`) and the decision
   (`data.decision_ref`).

Condition 5 means one answer opens one node. Two nodes that wait for the same
decision text need two questions and two answers.

The question to the owner, and the answer:

```json
{"v": 1, "k": "question", "need": "answer",
 "data": {"work": "W-example-a", "decision_ref": "ab12ab12ab12ab12",
          "text": "Apply the change to one service? Rollback: restore the copy."}}
```

```json
{"v": 1, "k": "decision", "need": "none",
 "data": {"disposition": "approve", "text": "approved ab12ab12ab12ab12"}}
```

What the arbiter cannot do, by the same rules: answer for the owner, open a
blocked node with its own message, or reuse an old owner message (for example
the one the work was started under) as an approval.

`mesh_cli.py rebuild` replays the bus into a fresh projection. An opening that
the messages on the bus refute does not survive the replay. An opening whose
owner answer has already expired from the bus is kept as recorded.

## Set the address

The default `pm` address in the code is `grok`. Set your own:

```json
{"pm": "lead"}
```

Save it as `mesh-limits.json` in the bus state directory. The same file can
lower or raise the per-agent limits (`open_claims`, `decisions_per_agent` and
the others in `DEFAULT_LIMITS`).

## The working convention

Nothing below is checked by code. It is a description of the role that the
rules above were built for. Use it, change it or ignore it.

- **Coordinate, do not execute.** The arbiter splits a task into nodes, sees
  that each has one holder, reads the results and reports. Changes are made by
  the agents that hold the nodes.
- **Review before the owner sees it.** A proposal from an executor goes to the
  arbiter first. The arbiter checks it against the facts and sends it back for
  repair when it is wrong. The owner sees results, conflicts and decisions,
  not raw drafts.
- **Carry the owner's word exactly.** An approval is passed on in the owner's
  own words, with its scope. The arbiter does not widen it. A general "yes"
  covers the item it answered and nothing next to it.
- **Ask at the real decision point.** A question that depends on unfinished
  work waits until the work is done. Decisions that can be undone are made
  without asking; a production change, an irreversible step or spending is
  the owner's.
- **Keep open decisions visible.** Each open decision has a short stable
  number. Every report ends with the decisions that still wait, so that a
  question is not lost when the owner answers later.
- **Say what was not checked.** A report separates what was verified, what
  failed and what nobody looked at.

## Verified

`components/integrity-llm-bus/tests/live/test_mesh_store_owner_answer.py`
runs the projection on an in-memory bus table with synthetic agents:

- 15 owner messages that must not open a node (refusal, deferral, wrong
  recipient, missing or short reference, reference outside the text, a reply
  to the wrong question, a question older than the request, a question about
  the twin node);
- an approval that opens its own node and not the twin node;
- an approval of the holder's own question;
- an arbiter message cited as an owner answer;
- the owner as sender or recipient of a mesh message;
- cancel by the arbiter and by another agent;
- the `pm` address read from `mesh-limits.json`;
- `rebuild` after an accepted opening, after expiry of the answer or the
  question, and after a forged opening record.

## Not verified

- The working convention. No test or measurement shows that an agent follows
  it, or that work goes better with it.
- The role with real agents of several vendors on a running bus. The tests
  call the projection in one process.
- Who may post as `owner`. That is decided by the bus and the hub before a
  message reaches the projection; see the
  [LLM bus README](../components/integrity-llm-bus/README.md).
