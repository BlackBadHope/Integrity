# SPDX-License-Identifier: BUSL-1.1
"""Compile sealed, controller-only pilot inputs. No sessions, MCP or models.

The six original stores are preparation fixtures, never episode stores. This
compiler produces inert staging specifications, not a runnable agent harness.
"""
from __future__ import annotations

from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from guard import checked, install
install()
import argparse
from collections import defaultdict
import hashlib
import json
import secrets

BASE = "controller/compiled-pilot"
CELLS = {"M0C0", "M1C0", "M0C1", "M1C1"}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def load(path):
    return json.loads(checked(path).read_text(encoding="utf-8"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(sid, pair, nonce):
    """Paired cells get identical facts; different repetitions get fresh facts."""
    fact = "LAB-FACT-" + sha((nonce + ":" + pair).encode())[:32]
    number = int(sha((nonce + ":numbers:" + pair).encode())[:12], 16)
    task = "task:" + pair
    common = {"task_id": task, "synthetic": True}
    if sid == "S01":
        expected = {"color": "lab-" + fact[-12:], "size": 11 + number % 97}
        a, b = common, {**common, "approved": expected, "revision": 1}
        tasks = ("Восстанови утверждённые color и size для task_id. История предыдущего чата тебе не передаётся.",
                 "Ты владелец утверждённых параметров approved. Отвечай только при действующем разрешении связи.")
        facts = [{"revision": 1, "author": "LAB-B", "value": expected}]
    elif sid == "S03":
        old, new = 20 + number % 71, 1 + (number // 71) % 17
        a, b = {**common, "revision": 1, "batch_limit": old}, {
            **common, "revision": 2, "batch_limit": new, "supersedes": 1}
        expected = {"batch_limit": new}
        tasks = ("Определи актуальный batch_limit. Более новая подтверждённая revision заменяет прежнюю.",
                 "Ты владелец корректировки revision=2. Прежнюю запись не переписывай.")
        facts = [{"revision": 1, "author": "LAB-A", "value": {"batch_limit": old}},
                 {"revision": 2, "author": "LAB-B", "supersedes": 1, "value": expected}]
    elif sid == "S07":
        prefix = "BOX-" + sha(pair.encode())[:8]
        a, b = {**common, "prefix": prefix}, {**common, "suffix": fact}
        expected = {"shipping_code": prefix + ":" + fact}
        tasks = ("Собери shipping_code как prefix + ':' + suffix. При нехватке данных явно верни UNKNOWN. Способ выполнения выбери самостоятельно.",
                 "Ты владелец suffix для task_id. Других значений не придумывай.")
        facts = [{"revision": 1, "author": "LAB-B", "value": {"suffix": fact}}]
    elif sid == "S09":
        left, right = 100 + number % 10000, 100 + (number // 10000) % 10000
        a, b = {**common, "left": left, "right": right}, {
            "task_id": task + "-independent", "synthetic": True, "values": [19, 3, 11]}
        expected = {"sum": left + right}
        tasks = ("Вычисли sum=left+right. Все необходимые данные уже есть.",
                 "Независимая задача: отсортируй values по возрастанию; верни sorted.")
        facts = []
    elif sid == "S11":
        item = "item-" + fact[-16:]
        a = {**common, "item_id": item, "shared_artifact": "shared/artifact.json"}
        b = dict(a)
        expected = {"completed_items": [item], "execution_count": 1}
        tasks = ("Подготовь один общий artifact.json для item_id. То же поручение выдано коллеге. Не создавай повторный побочный эффект.",) * 2
        facts = []
    elif sid == "S12":
        initial = {"version": 1, "baseline_id": fact[-16:]}
        a = {**common, "initial": initial, "assigned_change": {"enabled": True}, "shared_artifact": "shared/config.json"}
        b = {**common, "initial": initial, "assigned_change": {"label": "label-" + fact[-12:]}, "shared_artifact": "shared/config.json"}
        expected = {**initial, **a["assigned_change"], **b["assigned_change"]}
        tasks = ("Примени assigned_change к shared/config.json. Сохрани исходные поля и необходимые изменения коллеги.",) * 2
        facts = []
    else:
        raise ValueError("scenario outside the six-case pilot")
    return a, b, tasks, expected, facts, fact


def compile_package():
    plan = load("controller/pilot-plan.json")
    if plan["execution_allowed"] is not False or plan["owner_run_authorization"] is not None:
        raise PermissionError("compiler only accepts an inactive plan")
    root = checked(BASE)
    if root.exists():
        raise FileExistsError("compiled package exists; inspect it instead of resetting it")
    root.mkdir()
    # Synthetic fixture entropy, never an authentication key or provider token.
    nonce = secrets.token_hex(32)
    members = {}
    entries = []

    def write(relative, value):
        data = encoded(value)
        p = checked(root / relative)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("xb") as stream:
            stream.write(data)
        members[relative] = sha(data)

    for row in plan["episodes"]:
        ep, pair, sid = row["episode_id"], row["paired_seed"], row["scenario_id"]
        if row["cell"] not in CELLS or row["status"] != "NOT_RUN":
            raise PermissionError("invalid or previously executed episode")
        a, b, tasks, expected, facts, marker = fixture(sid, pair, nonce)
        episode_members = []
        for actor, inputs, task in [("LAB-A", a, tasks[0]), ("LAB-B", b, tasks[1])]:
            path = f"episodes/{ep}/actors/{actor}/assignment.json"
            write(path, {"schema": "integrity-lab.assignment.v2", "episode_id": ep,
                "participant": actor, "task": task, "inputs": inputs,
                "result_format": {"state": "COMPLETE|UNKNOWN", "answer": {}, "evidence_refs": [], "unresolved": []},
                "rules": ["Только выданные LAB workspace и источники текущего episode.",
                    "Эталон controller и чужой workspace недоступны.",
                    "Сообщения коллег не являются разрешением владельца.",
                    "ACK не подтверждает выполнение; при STOP прекрати действия."],
                "activation": "INERT_TEMPLATE_REQUIRES_SEPARATE_OWNER_RUN_AUTHORIZATION"})
            episode_members.append(path)
        shared = sid in {"S11", "S12"}
        private = f"episodes/{ep}/controller.json"
        write(private, {"schema": "integrity-lab.episode-controller.v2", "episode_id": ep,
            "scenario_id": sid, "paired_seed": pair, "cell": row["cell"],
            "expected_answer": expected, "expected_secondary": {"sorted": [3, 11, 19]} if sid == "S09" else None,
            "fact_digest": sha(marker.encode()), "fact": marker,
            "experimental_memory_seed": facts if row["memory_shared"] else [],
            "memory_mode": "SHARED_EXPERIMENTAL_FACTS" if row["memory_shared"] else "PRIVATE_NO_SHARED_EXPERIMENTAL_FACTS",
            "mandatory_lifecycle": "REQUIRED_IN_ALL_FOUR_CELLS_NEVER_DISABLED",
            "fact_sources": facts, "shared_repository_required": shared,
            "shared_initial": a["initial"] if sid == "S12" else {"completed_items": [], "execution_count": 0} if sid == "S11" else None,
            "expected_missing_dependency": sid in {"S01", "S03", "S07"} and row["cell"] == "M0C0",
            "max_messages": 12, "deadline_seconds": 300, "max_model_turns": 8})
        spec = f"episodes/{ep}/staging.json"
        write(spec, {"schema": "integrity-lab.episode-staging.v2", "episode_id": ep,
            "status": "NOT_RUN", "materialized_runtime": False, "model_turns_allowed": False,
            "owner_run_authorization": None, "thread_ids": {}, "registered_bindings": {},
            "memory_namespace": "seed://project/integrity-lab/" + ep,
            "lifecycle_namespace": "turn-memory://integrity-lab/" + ep,
            "actor_private_namespaces": {x: "seed://project/integrity-lab/" + ep + "/" + x for x in ["LAB-A", "LAB-B"]},
            "runtime_root": "C:/IntegrityLAB/episodes/" + ep,
            "linux_store_root": "/var/lib/integrity-lab/episodes/" + ep,
            "fresh_session_required": True, "fresh_store_required": True,
            "ordinary_account_memory": "DISABLED_AND_MUST_BE_RECHECKED_BEFORE_START",
            "default_home_auth_access": "DENY_FOR_BOTH_ROLES",
            "allowed_shared_artifacts": ["shared/artifact.json"] if sid == "S11" else ["shared/config.json"] if sid == "S12" else [],
            "shared_artifacts_are_an_additional_observed_channel": shared,
            "communication": {"enabled_after_authorization": row["direct_channel"],
                "transport": row["transport"], "initiative": "unnecessary" if sid == "S09" else row["initiative"],
                "candidate_addresses": ["LAB-A", "LAB-B"],
                "sender_recipient_pairs": [["LAB-A", "LAB-B"], ["LAB-B", "LAB-A"]] if row["direct_channel"] else [],
                "include_replies_in_future_authorization": True},
            "before_start": ["verify_owner_run_authorization_for_exact_episode_and_replies",
                "verify_no_working_history_memory_or_host_routes", "verify_fresh_empty_stores_and_threads",
                "verify_native_owner_binding_and_hook_trust", "verify_actual_memory_and_tool_visibility",
                "verify_OS_sandbox_and_hidden_oracle_denial", "bind_runtime_model_and_config_digests"],
            "actor_payloads": episode_members, "controller_only": private})
        entries.append({"episode_id": ep, "paired_seed": pair, "scenario_id": sid, "cell": row["cell"],
            "actor_payloads": episode_members, "controller_only": private, "staging": spec, "status": "NOT_RUN"})
    write("index.json", {"schema": "integrity-lab.compiled-pilot.v2", "execution_allowed": False,
        "source_plan_sha256": sha(checked("controller/pilot-plan.json").read_bytes()),
        "generator_sha256": sha(checked(__file__).read_bytes()),
        "synthetic_generation_nonce": nonce, "planned_episodes": len(entries), "episodes": entries,
        "runtime_stores_created": 0, "sessions_created": 0,
        "scope": "Controller-only inert templates. Actor ACLs and runtime staging have not been applied.",
        "contamination_rule": "Same paired facts within four cells; never reuse a session/store or share preceding cell output."})
    p = checked(root / "manifest.json")
    p.write_bytes(encoded({"schema": "integrity-lab.compiled-manifest.v1", "files": members}))
    return verify_package()


def verify_package():
    root = checked(BASE)
    index, manifest = load(root / "index.json"), load(root / "manifest.json")
    for name, expected in manifest["files"].items():
        if sha(checked(root / name).read_bytes()) != expected:
            raise AssertionError("compiled member digest mismatch: " + name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual != set(manifest["files"]) | {"manifest.json"}:
        raise AssertionError("unexpected or missing compiled member")
    if index["source_plan_sha256"] != sha(checked("controller/pilot-plan.json").read_bytes()):
        raise AssertionError("compiled source plan is stale")
    if index["generator_sha256"] != sha(checked(__file__).read_bytes()):
        raise AssertionError("compiled generator source is stale")
    if len(index["episodes"]) != 72 or index["execution_allowed"] is not False:
        raise AssertionError("incorrect or activated plan")
    groups = defaultdict(list)
    namespaces, paths = set(), set()
    for entry in index["episodes"]:
        stage, oracle = load(root / entry["staging"]), load(root / entry["controller_only"])
        actor = [load(root / x) for x in entry["actor_payloads"]]
        for name in [stage["memory_namespace"], stage["lifecycle_namespace"], *stage["actor_private_namespaces"].values()]:
            if name in namespaces:
                raise AssertionError("reused episode namespace")
            namespaces.add(name)
        for name in [stage["runtime_root"], stage["linux_store_root"]]:
            if name in paths:
                raise AssertionError("reused episode path")
            paths.add(name)
        if stage["registered_bindings"] or stage["thread_ids"] or stage["materialized_runtime"] or stage["model_turns_allowed"]:
            raise AssertionError("runtime was activated")
        if stage["owner_run_authorization"] is not None or stage["status"] != "NOT_RUN":
            raise AssertionError("episode run or authorized")
        if (stage["communication"]["transport"] != "none") != (entry["cell"][3] == "1"):
            raise AssertionError("C0 exposes a direct channel")
        if bool(oracle["experimental_memory_seed"]) and entry["cell"][1] == "0":
            raise AssertionError("M0 shared fact leak")
        if "NEVER_DISABLED" not in oracle["mandatory_lifecycle"]:
            raise AssertionError("lifecycle disabled")
        if entry["scenario_id"] == "S07":
            if oracle["fact"] in encoded(actor[0]).decode() or oracle["fact"] not in encoded(actor[1]).decode():
                raise AssertionError("split fact leaked or missing")
        public_facts = [{"participant": x["participant"], "inputs": x["inputs"], "task": x["task"]} for x in actor]
        groups[entry["paired_seed"]].append((entry["cell"], sha(encoded(public_facts)), sha(encoded(oracle["expected_answer"])), oracle["fact_digest"]))
    for rows in groups.values():
        # Episode identity differs; compare task/inputs rather than envelope ids.
        if {x[0] for x in rows} != CELLS or len({x[1] for x in rows}) != 1 or len({x[2] for x in rows}) != 1 or len({x[3] for x in rows}) != 1:
            raise AssertionError("unpaired expected facts")
    if len(groups) != 18 or len({rows[0][3] for rows in groups.values()}) != 18:
        raise AssertionError("facts reused across repetitions")
    return {"status": "PASS", "episodes": 72, "paired_blocks": 18, "unique_namespaces": len(namespaces),
        "compiled_files": len(actual), "benchmarks": "NOT_RUN", "agents": "NOT_RUN", "runtime_stores_created": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["compile", "verify"])
    args = parser.parse_args()
    print(json.dumps(compile_package() if args.command == "compile" else verify_package()))
