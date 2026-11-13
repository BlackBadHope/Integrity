# SPDX-License-Identifier: BUSL-1.1
"""Bounded OFFLINE preparation checks. Never executes the laboratory tasks."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parent))
from guard import ROOT, checked, actor_path, readonly_db, install
install()
import ast
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import time
sys.path.insert(0,str(checked("vendor")))
from seed_catalog_runtime.seed_catalog import SeedCatalog


def load(name): return json.loads(checked(name).read_text(encoding="utf-8"))
def digest(p): return hashlib.sha256(checked(p).read_bytes()).hexdigest()
def require(value, message):
    if not value: raise AssertionError(message)
def denied(call):
    try: result=call()
    except PermissionError: return
    if hasattr(result,"close"): result.close()
    raise AssertionError("operation was not denied")


def main():
    start=time.monotonic()
    checks=[]
    config=load("lab.json")
    manifest=load("PACKAGE-MANIFEST.json")
    package_digest=digest("PACKAGE-MANIFEST.json")
    db_before={k:digest(v) for k,v in config["stores"].items()}
    def check(name, fn):
        try:
            fn()
            checks.append({"claim":name,"status":"PASS"})
        except Exception as e:
            checks.append({"claim":name,"status":"FAIL","reason":type(e).__name__+": "+str(e)[:200]})
    def files():
        for name, expected in manifest["files"].items():
            require(digest(name)==expected,"package member hash mismatch: "+name)
        for directory,dirs,names in os.walk(ROOT):
            dirs[:]=[x for x in dirs if x not in {".git","runtime","state","evidence","__pycache__"}]
            for name in names:checked(Path(directory)/name)
    check("package_hashes_and_no_reparse_or_hardlinks",files)
    def config_gate():
        require(config["root"]==str(ROOT),"wrong root")
        require(config["phase"] in {"PREPARED_NO_EXECUTION","PILOT_BLOCKED"},"unsafe phase")
        for name in ["agents_enabled","network_enabled","inherit_user_runtime"]:
            require(config[name] is False,"enabled capability: "+name)
        if config["benchmarks_enabled"]:
            auth=load("controller/efficiency-authorization.json")
            require(config.get("benchmark_scope")=="BOUNDED_EFFICIENCY_ONLY","unbounded benchmark capability")
            require(auth["max_model_subjects"]==16 and auth["max_user_turns_per_subject"]==1,"benchmark budget changed")
            require(auth["full_72_Native_pilot_execution_allowed"] is False and auth["working_data_access"] is False,"benchmark scope broadened")
            require(digest("controller/efficiency-smoke-fixtures.json")==auth["fixture_sha256"],"benchmark fixture changed")
        require(config["registered_participants"]==[],"participant registered")
        for adapter in config["adapters"].values():
            require(adapter.get("running",False) is False and adapter.get("endpoint") is None,"persistent or network adapter configured")
        if config["phase"]=="PILOT_BLOCKED":
            require(config["pilot_execution_allowed"] is False,"blocked pilot activated")
            require(config["adapters"]["integrity_mcp"]["native_lifecycle"]=="BLOCKED_POSIX_CUSTODY","Native blocker hidden")
            require(config["managed_hooks_isolation"]=="FAIL_SYSTEM_HOOKS_INHERITED","system hook contamination hidden")
    check("adapter_configuration_remains_local_non_executing_and_fail_closed",config_gate)
    def syntax():
        for name in manifest["files"]:
            if name.endswith(".py"): ast.parse(checked(name).read_text(encoding="utf-8"))
    check("all_python_sources_parse",syntax)
    def pinning():
        provenance=load("provenance.json")
        for name,expected in provenance["unchanged_modules"].items():
            require(digest("vendor/seed_catalog_runtime/"+name)==expected,"vendored source changed")
        require(provenance["production_data_copied"] is False,"production data declared")
    check("vendored_SeedCatalog_source_pinned",pinning)
    def store_paths():
        paths=[checked(x).resolve() for x in config["stores"].values()]
        require(len(paths)==len(set(paths)),"store paths alias")
        identities=[(x.stat().st_dev,x.stat().st_ino) for x in paths]
        require(len(identities)==len(set(identities)),"store file identity aliases")
    check("six_store_files_have_distinct_identities",store_paths)
    markers={}
    def catalogs():
        for name in ["shared","session_a","session_b","negative_control"]:
            cat=SeedCatalog(checked(config["stores"][name]),immutable=True)
            cat.verify(expected_event_count=1)
            expected_ns="seed://project/integrity-lab-"+name.replace("_","-")
            require(cat.bound_source_namespace()==expected_ns,"wrong Seed namespace")
            require(cat.bound_source_identity()=="lab-only:"+config["project_id"]+":"+name,"wrong source identity")
            event=cat.event_at(1)
            require(event["details"].get("synthetic") is True,"non-synthetic seed event")
            markers[name]=load("state/PREPARED.json")["markers"][name]
            require(markers[name] in event["summary"],"own store marker missing")
        require(len(set(markers.values()))==4,"store markers alias")
        for name in markers:
            with closing(readonly_db(config["stores"][name])) as db:
                text="\n".join(db.iterdump())
                for other in markers:
                    if other!=name: require(markers[other] not in text,"foreign LAB marker found")
    check("real_SeedCatalog_verify_and_LAB_marker_separation",catalogs)
    def db_gate():
        for p in config["stores"].values():
            with closing(readonly_db(p)) as db:
                require(db.execute("PRAGMA quick_check").fetchone()[0]=="ok","SQLite integrity failure")
        for name,tables in [("queue",["participants","messages","receipts"]),("results",["episodes","observations"])]:
            with closing(readonly_db(config["stores"][name])) as db:
                for table in tables:
                    require(db.execute("SELECT COUNT(*) FROM "+table).fetchone()[0]==0,"activity already present")
    check("SQLite_health_empty_queue_no_benchmark_results",db_gate)
    def readonly_gate():
        with closing(readonly_db(config["stores"]["queue"])) as db:
            try: db.execute("CREATE TABLE forbidden_probe(x)")
            except sqlite3.OperationalError as e:
                require("readonly" in str(e).lower(),"unexpected write rejection")
            else: raise AssertionError("readonly connection allowed a write")
    check("validation_SQL_connections_reject_writes",readonly_gate)
    import lab_config
    working=Path(lab_config.lookup(config,"host.denied_sentinels.working_source"))
    working_tree=working.parent
    working_bus=Path(lab_config.lookup(config,"host.denied_sentinels.working_bus_database"))
    check("production_tree_read_denied_before_open",lambda:denied(lambda:open(str(working),"rb")))
    check("production_bus_SQL_read_denied_before_connect",lambda:denied(lambda:sqlite3.connect(working_bus.as_uri()+"?mode=ro",uri=True)))
    check("owner_Codex_tree_read_denied_before_open",lambda:denied(lambda:open(str(Path.home()/".codex"/"AGENTS.md"),"rb")))
    def escapes():
        share="\\\\localhost\\"+(working_tree.drive[:1] or "C")+"$\\"+str(working_tree.relative_to(working_tree.anchor))+"\\x"
        for raw in [str(working_tree/"x"),"..\\"+working_tree.name+"\\x",r"D:relative",share,r"state\probe:stream",r"state\bad."]:
            denied(lambda value=raw:checked(value))
        for raw in [r"..\LAB-B\input.json",r"..\..\..\controller\oracles\S02.json",str(working)]:
            denied(lambda value=raw:actor_path("S02","LAB-A",value))
        require(actor_path("S02","LAB-A","input.json").is_file(),"allowed actor input unavailable")
    check("absolute_UNC_ADS_traversal_and_foreign_role_paths_denied",escapes)
    check("network_creation_denied",lambda:denied(lambda:socket.socket()))
    check("child_process_launch_denied",lambda:denied(lambda:subprocess.Popen([sys.executable,"-V"])))
    def scenario_gate():
        cases=load("controller/scenarios.json")["scenarios"]
        require([x["id"] for x in cases]==[f"S{i:02}" for i in range(1,25)],"scenario coverage mismatch")
        for case in cases:
            require(case["state"]=="NOT_RUN","scenario state changed")
            require(set(case["contrast"])=={"factor","A","B"},"missing paired contrast")
            oracle=load(case["oracle"])
            require("expected_A" in oracle and "expected_B" in oracle,"missing oracle")
            for actor,path in case["actor_inputs"].items():
                require(load(path)["participant"]==actor,"actor fixture mismatch")
        oracle=load("controller/oracles/S02.json")
        a=actor_path("S02","LAB-A","input.json").read_text(encoding="utf-8")
        prompt=actor_path("S02","LAB-A","TASK_RU.md").read_text(encoding="utf-8")
        require(oracle["marker"] not in a+prompt,"hidden peer fact leaked into LAB-A")
        require(oracle["marker"] in actor_path("S02","LAB-B","input.json").read_text(encoding="utf-8"),"peer fact absent")
    check("24_paired_cases_role_inputs_and_hidden_fact_boundary",scenario_gate)
    def plan_gate():
        plan=load("controller/pilot-plan.json")
        require(plan["execution_allowed"] is False and plan["owner_run_authorization"] is None,"plan activated")
        episodes=plan["episodes"]
        require(len(episodes)==72 and len({x["episode_id"] for x in episodes})==72,"episode count/id mismatch")
        require(set(Counter(x["paired_seed"] for x in episodes).values())=={4},"unpaired seed")
        for row in episodes:
            require(row["status"]=="NOT_RUN" and row["fresh_store_required"] and row["fresh_session_required"],"episode executed or contaminated")
            require(row["memory_shared"]==(row["cell"][1]=="1") and row["direct_channel"]==(row["cell"][3]=="1"),"factor mismatch")
    check("72_episode_plan_is_paired_inactive_and_fresh",plan_gate)
    def compiled_pilot_gate():
        from pilot_package import verify_package
        require(verify_package()["status"]=="PASS","compiled pilot verification failed")
    check("compiled_72_episode_payloads_pairing_unique_namespaces_and_hidden_facts",compiled_pilot_gate)
    def review_gate():
        from episode_review import regression_gate
        result=regression_gate()
        require(result["status"]=="PASS" and result["episodes_run"]==0,"passive review gate failed")
        checked("evidence/PASSIVE-REVIEW-REGRESSION.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    check("passive_review_rejects_ACK_promotion_wrong_identity_STOP_and_false_silence",review_gate)
    check("validation_did_not_change_any_store_bytes",lambda:require(db_before=={k:digest(v) for k,v in config["stores"].items()},"validation changed a database"))
    failures=[x for x in checks if x["status"]=="FAIL"]
    report={"schema":"integrity-lab.offline-validation.v1","timestamp_utc":datetime.now(timezone.utc).isoformat(),
      "package_manifest_sha256":package_digest,"python":sys.version.split()[0],"sqlite":sqlite3.sqlite_version,
      "status":"PASS" if not failures else "FAIL","claim_scope":"offline prepared stores and guarded local toolkit only",
      "checks":checks,"elapsed_seconds":round(time.monotonic()-start,3),"benchmarks":"FULL_72_NATIVE_EPISODES_NOT_RUN","benchmark_agents":"FULL_NATIVE_PARTICIPANTS_NOT_RUN",
      "bounded_native_canary":"SEPARATE_RUNTIME_EVIDENCE_evidence/NATIVE-CANARY-RESULT.json",
      "bounded_efficiency_benchmarks":"SEPARATE_RUNTIME_EVIDENCE_evidence/EFFICIENCY-BENCHMARK-SUMMARY.json",
      "runtime_mcp_isolation":"NOT_EVALUATED_BY_THIS_OFFLINE_GATE","OS_process_sandbox":"NOT_EVALUATED_BY_THIS_OFFLINE_GATE","production_canary_write":"NOT_RUN_NOT_AUTHORIZED",
      "runtime_evidence":["evidence/MCP-PREFLIGHT.json","evidence/MXC-ISOLATION.json","evidence/CONFIG-READBACK.json"],
      "limitation":"Python guard cannot confine another process or a future agent. Runtime evidence is separate; the full Native pilot remains blocked.",
      "store_sha256":db_before,"command":"python -I -B tools/validate.py"}
    checked("evidence/OFFLINE-VALIDATION.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"checks":len(checks),"failed":failures,"elapsed_seconds":report["elapsed_seconds"],"benchmarks":report["benchmarks"],"benchmark_agents":report["benchmark_agents"],"bounded_native_canary":"SEPARATE_RUNTIME_EVIDENCE","bounded_efficiency_benchmarks":report["bounded_efficiency_benchmarks"]},ensure_ascii=False))
    return 1 if failures else 0


if __name__=="__main__":
    raise SystemExit(main())
