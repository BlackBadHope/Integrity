# Glossary

[Documentation](README.md) · [Project README](../README.md)

Twelve words this project uses everywhere, in plain terms. Each entry links to
the page that defines it exactly.

| Word | In plain terms | Where it is defined |
| --- | --- | --- |
| **Seed** | The shared record: an append-only log of events. Agents of every vendor write to it; nothing is overwritten, a correction is appended next to the claim. Reading it never grants permission. | [How it works](../README.md#how-it-works) |
| **Mind** | A read-only view built from Seed: tasks, goals, facts, contradictions, stale claims and known routes. It is computed, never edited by hand. | [How it works](../README.md#how-it-works) |
| **Turn** | One unit of an agent's work: from the prompt it received to its last reply. | [One turn](../README.md#one-turn) |
| **Admission** | The start of a turn: the agent registers the turn and gets a bounded slice of memory (at most 8 KB) bound to one fixed snapshot. Until then the gate denies other tools. | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| **Close receipt** | The signed record that a turn ended, listing the events it wrote, or saying it wrote none. | [LOCAL_MEMORY.md](LOCAL_MEMORY.md) |
| **Coverage gap** | A turn that was registered but has no close receipt, for example because the agent stopped early. It stays visible as debt; it is not guessed as "nothing happened". | [One turn](../README.md#one-turn) |
| **Work claim** and **fence token** | A claim says "I am working on this task". Each new claim of the same task gets a higher number, the fence token, so a late writer holding an old claim can be told apart. | [LOCAL_MEMORY.md](LOCAL_MEMORY.md) |
| **Grant** | A signed permission that can be used once, for one stated change. It is the only thing that grants authority; a memory read or a plan never does. | [ARCHITECTURE.md](../ARCHITECTURE.md#authorization-lifecycle) |
| **Custody** | Keeping a grant or a record so that it can be used exactly once and checked afterwards: reserved, consumed against independent observations, with a receipt. A second use is detected as a replay. | [ARCHITECTURE.md](../ARCHITECTURE.md#authorization-lifecycle) |
| **Uroboros** | Procedural memory: a verified piece of work becomes a route that a later agent is offered at admission, as a hint to check, never as permission. | [UROBOROS.md](UROBOROS.md) |
| **Guardian** | The protocol core: canonical JSON, signatures, the signed Ledger, one-use grants and independent observation. | [How it works](../README.md#how-it-works) |
| **Home** | An optional private archive kept apart from project memory (Seed). | [integrity-home](../components/integrity-home/README.md) |

Internal module names such as `medor`, `synapse`, `connectome` and `atlas`
name parts of the implementation; they are not words a user needs.
[ARCHITECTURE.md](../ARCHITECTURE.md) maps each module group to its role.
