"""The two Windows hooks know a core tool by its name together with its server.

The functions under test are taken from the published hook files by the
PowerShell parser and run as they are. The hooks themselves are not run here:
they need a configured installation.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


COMPONENT = Path(__file__).resolve().parents[1]
PACKAGE = COMPONENT / "src" / "integrity_client_memory"
WINDOWS = PACKAGE / "resources" / "windows"
OWN = "mcp__integrity_client_memory__"
OTHER = "mcp__integrity_local_memory__"
COMMON = [
    "Get-Value", "Get-OwnMemoryToolName", "Is-AppendTool", "Is-ContextAdmissionTool",
    "Is-CurrentContextAdmissionTool", "Is-IntegrityMemoryTool", "Is-SubstantiveAction",
]
# File name -> the functions to run, and how many comparisons with a core tool
# name the file has (all of them, and different ones).
HOOKS = {
    "admission-system.ps1": (COMMON + ["Is-ArchiveTool"], 17, 11),
    "admission.ps1": (COMMON, 4, 4),
}

HARNESS = r"""
param([string]$HookPath, [string]$CasesPath, [string]$Functions)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($HookPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'the hook file does not parse' }
$wanted = @($Functions -split ',')
$found = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $wanted
}, $true))
if ($found.Count -ne $wanted.Count) { throw 'the hook file does not define each function once' }
foreach ($definition in $found) { . ([scriptblock]::Create($definition.Extent.Text)) }
$rows = foreach ($payload in @(Get-Content -LiteralPath $CasesPath -Raw | ConvertFrom-Json)) {
    [ordered]@{
        name = [string]$payload.tool_name
        own = [string](Get-OwnMemoryToolName -Payload $payload)
        memory = [bool](Is-IntegrityMemoryTool -Payload $payload)
        append = [bool](Is-AppendTool -Payload $payload)
        admission = [bool](Is-ContextAdmissionTool -Payload $payload)
        current = [bool](Is-CurrentContextAdmissionTool -Payload $payload)
        archive = if ($wanted -contains 'Is-ArchiveTool') { [bool](Is-ArchiveTool -Payload $payload) } else { $false }
        action = [bool](Is-SubstantiveAction -Payload $payload)
    }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
"""


def run_hook_functions(tmp_path, hook, names):
    shell = shutil.which("pwsh")
    if shell is None:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail("pwsh is expected on every CI runner")
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([{"tool_name": name} for name in names]), encoding="utf-8")
    done = subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         str(WINDOWS / hook), str(cases), ",".join(HOOKS[hook][0])],
        capture_output=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    rows = json.loads(done.stdout.decode("utf-8"))
    assert [row["name"] for row in rows] == list(names)
    return {row["name"]: row for row in rows}


def core_tool_names():
    catalog = json.loads((PACKAGE / "data" / "tools-current.json").read_text(encoding="utf-8"))
    names = [item["name"] for item in catalog.get("result", catalog)["tools"]]
    assert len(names) == len(set(names)) > 10
    assert all(re.fullmatch(r"integrity_[a-z0-9_]+", name) and "__" not in name for name in names)
    return names


@pytest.mark.parametrize("hook", sorted(HOOKS))
def test_a_tool_of_the_own_server_is_a_memory_tool(tmp_path, hook):
    names = core_tool_names()
    prefixes = (OWN, "integrity_client_memory__", "", "MCP__Integrity_Client_Memory__")
    rows = run_hook_functions(tmp_path, hook, [prefix + name for prefix in prefixes for name in names])
    for prefix in prefixes:
        for name in names:
            row = rows[prefix + name]
            assert (row["own"], row["memory"], row["action"]) == (name, True, False), row
            assert row["append"] is (name == "integrity_append_event"), row
            assert row["current"] is (name == "integrity_context_admission_current_turn"), row
            assert row["admission"] is (
                name in {"integrity_context_admission", "integrity_context_admission_current_turn"}
            ), row
    assert rows[OWN + "integrity_append_event"]["append"] is True
    assert rows[OWN + "integrity_context_admission_current_turn"]["current"] is True


@pytest.mark.parametrize("hook", sorted(HOOKS))
def test_a_tool_of_another_server_is_an_action_whatever_its_name(tmp_path, hook):
    names = core_tool_names()
    foreign = [OTHER + name for name in names] + [
        OTHER + "integrity_archive_import",
        OTHER + "lm_append_event",
        "mcp__other__integrity_context_admission_current_turn",
        "integrity_local_memory__integrity_append_event",
        "mcp__integrity_client_memory_copy__integrity_append_event",
        "mcp__copy__integrity_client_memory__integrity_append_event",
        "mcp__integrity_append_event",
        # The server part is longer than the own server name.
        "mcp__integrity_client_memory__x__integrity_append_event",
        "mcp__integrity_client_memory__integrity__append_event",
    ]
    rows = run_hook_functions(tmp_path, hook, foreign + ["other.integrity_append_event"])
    for name in foreign:
        assert rows[name] == {
            "name": name, "own": "", "memory": False, "append": False, "admission": False,
            "current": False, "archive": False, "action": True,
        }, rows[name]
    # Codex does not form such a name for an MCP tool. It carries no server, so it is compared
    # whole, and no pattern matches it.
    assert rows["other.integrity_append_event"] == {
        "name": "other.integrity_append_event", "own": "other.integrity_append_event", "memory": False,
        "append": False, "admission": False, "current": False, "archive": False, "action": True,
    }


def codex_hook_tool_name(server, tool, prefixed=True):
    """The name Codex 0.163.0 gives a hook for an MCP tool, repeated from its source.

    codex-mcp/src/tools.rs and codex-mcp/src/mcp/mod.rs: the namespace is the server name with
    every character outside [A-Za-z0-9_] replaced by "_", with "mcp__" in front unless the
    prefix is switched off. core/src/tools/handlers/mcp.rs, hook_tool_name: the namespace
    without trailing "_", then "__", then the tool name without leading "_", and "mcp__" in
    front if it is not there yet. The hook input (hooks/src/schema.rs) has tool_name and no
    field for the server.
    """
    def sanitize(value):
        return re.sub(r"[^A-Za-z0-9_]", "_", value) or "_"

    namespace = sanitize(server) + "__"
    if prefixed and not namespace.startswith("mcp__"):
        namespace = "mcp__" + namespace
    joined = namespace.rstrip("_") + "__" + sanitize(tool).lstrip("_")
    return joined if joined.startswith("mcp__") else "mcp__" + joined


def test_the_name_codex_forms_is_the_form_the_hook_takes_apart():
    assert codex_hook_tool_name("memory", "create_entities") == "mcp__memory__create_entities"
    assert codex_hook_tool_name("foo", "exec_command", prefixed=False) == "mcp__foo__exec_command"
    assert codex_hook_tool_name("integrity_client_memory", "integrity_append_event") == (
        OWN + "integrity_append_event"
    )
    assert codex_hook_tool_name("file.system", "read-file") == "mcp__file_system__read_file"


@pytest.mark.parametrize("hook", sorted(HOOKS))
def test_names_as_codex_forms_them(tmp_path, hook):
    names = core_tool_names()
    own = {codex_hook_tool_name("integrity_client_memory", name, prefixed): name
           for name in names for prefixed in (True, False)}
    servers = ["integrity_local_memory", "integrity", "integrity_client_memory2", "memory", "integrity.client"]
    other = [codex_hook_tool_name(server, name, prefixed)
             for server in servers for name in names for prefixed in (True, False)]
    rows = run_hook_functions(tmp_path, hook, sorted(set(own) | set(other)))
    for shown, name in own.items():
        assert (rows[shown]["own"], rows[shown]["memory"], rows[shown]["action"]) == (name, True, False)
    for shown in other:
        assert (rows[shown]["own"], rows[shown]["memory"], rows[shown]["action"]) == ("", False, True)


@pytest.mark.parametrize("hook", sorted(HOOKS))
def test_other_names_keep_their_meaning(tmp_path, hook):
    rows = run_hook_functions(tmp_path, hook, [
        "shell", OWN + "integrity_archive_import", OWN + "integrity_archive_read", OWN + "lm_append_event",
        "mcp__codex_app__set_thread_title", "set_thread_title", "",
    ])
    assert (rows["shell"]["own"], rows["shell"]["memory"], rows["shell"]["action"]) == ("shell", False, True)
    archive = "Is-ArchiveTool" in HOOKS[hook][0]
    assert rows[OWN + "integrity_archive_import"]["archive"] is archive
    assert rows[OWN + "integrity_archive_read"]["archive"] is archive
    # The own server has no such tool, and the name is not a name of the core: the call is an action.
    assert (rows[OWN + "lm_append_event"]["memory"], rows[OWN + "lm_append_event"]["action"]) == (False, True)
    assert rows["mcp__codex_app__set_thread_title"]["action"] is False
    assert rows["set_thread_title"]["action"] is False
    assert (rows[""]["own"], rows[""]["memory"], rows[""]["action"]) == ("", False, False)


@pytest.mark.parametrize("hook", sorted(HOOKS))
def test_every_comparison_with_a_core_tool_name_uses_the_name_without_its_server(hook):
    """The main flow of a hook is not run here, so its comparisons are checked in the text."""
    lines = (WINDOWS / hook).read_text(encoding="utf-8").splitlines()
    comparison = re.compile(
        r"(\([^()]*\)|[^\s(]+)\s+-[ci]?(?:not)?match\s+'((?:\(\?i\))?[^']*integrity_[^']*)'"
    )
    own_call = re.compile(r"\(Get-OwnMemoryToolName -Payload \$payload\)", re.IGNORECASE)
    own_assignment = "    $name = Get-OwnMemoryToolName -Payload $Payload"
    # Two comparisons are not about whose tool it is: the check of the names in the tool list
    # of the own server, and the list of calls that change something.
    apart = {
        "^integrity_[a-z0-9_]{1,80}$",
        r"(?i)(?:apply_patch|\bEdit\b|\bWrite\b|NotebookEdit|integrity_append_event)",
    }
    seen = []
    for index, line in enumerate(lines):
        for operand, pattern in comparison.findall(line):
            if pattern in apart:
                continue
            seen.append(pattern)
            assert pattern.startswith("(?i)^integrity_") and pattern.endswith("$"), (index + 1, pattern)
            if operand == "$name":
                assert lines[index - 1] == own_assignment, index + 1
            else:
                assert own_call.fullmatch(operand), (index + 1, operand)
    assert (len(seen), len(set(seen))) == HOOKS[hook][1:], seen
    assert not [line for line in lines if re.search(r"tool_name\s+-[ci]?(?:not)?match", line)]


def test_both_hooks_have_the_same_function_for_the_own_name():
    def function_text(hook):
        text = (WINDOWS / hook).read_text(encoding="utf-8")
        start = text.index("function Get-OwnMemoryToolName {\n")
        return text[start:text.index("function Is-MeaningfulMutation {\n", start)]

    assert function_text("admission.ps1") == function_text("admission-system.ps1")
    assert function_text("admission.ps1").count("'integrity_client_memory'") == 1
    for hook in HOOKS:
        assert "mcp get integrity_client_memory --json" in (WINDOWS / hook).read_text(encoding="utf-8")
