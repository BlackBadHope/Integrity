# SPDX-License-Identifier: BUSL-1.1
"""Static checks of the lab tools in tools/lab. Nothing here starts a VM, a guest or the network."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import ipaddress
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "tools" / "lab"
EXAMPLE = LAB / "lab.example.json"
SPDX = "# SPDX-License-Identifier: BUSL-1.1"


def load_module(name: str):
    spec = importlib.util.spec_from_file_location("lab_tools_" + name, LAB / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def functions_from(path: Path, names: set[str], namespace: dict) -> dict:
    """Execute only the named top-level functions of a guest script (its imports need the guest)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in body} == names
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def python_sources() -> list[Path]:
    return sorted(LAB.glob("*.py"))


def test_every_python_source_compiles_and_carries_the_license_header() -> None:
    sources = python_sources()
    assert len(sources) >= 50
    for path in sources:
        text = path.read_text(encoding="utf-8")
        compile(text, str(path), "exec")
        lines = text.split("\n")
        first = lines[1] if lines[0].startswith("#!") else lines[0]
        assert first == SPDX, path.name


def test_powershell_sources_carry_the_license_header() -> None:
    for path in sorted(LAB.glob("*.ps1")):
        assert path.read_text(encoding="utf-8").split("\n")[0] == SPDX, path.name


def test_no_real_lab_configuration_is_shipped() -> None:
    assert not (LAB / "lab.json").exists()
    assert EXAMPLE.is_file()


def lab_config_mac(value: str, form: str) -> str:
    return load_module("lab_config").mac(value, form=form)


def leaves(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, prefix + "." + key if prefix else key)
    elif isinstance(value, list):
        for item in value:
            yield from leaves(item, prefix)
    else:
        yield prefix, value


def test_example_holds_only_documentation_addresses() -> None:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    documentation = [ipaddress.ip_network(x) for x in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    seen = 0
    for key, value in leaves(data):
        if not isinstance(value, str):
            continue
        for candidate in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", value):
            network = ipaddress.ip_network(candidate, strict=False)
            assert any(network.subnet_of(doc) for doc in documentation), key
            seen += 1
        # Per-user and service trees are built from parts so this test itself stays free of such paths.
        assert not value.startswith(tuple("/" + part + "/" for part in ("home", "srv"))), key
        assert "\\Users\\" not in value, key
    assert seen >= 6
    # The example MAC is a locally administered synthetic value (bare form, as lab_config.mac accepts).
    assert lab_config_mac(data["vms"]["linux"]["egress_mac"], "vbox").startswith("02000000")
    assert len(data["vms"]["windows"]["hostname"]) <= 15


def configuration_keys() -> set[str]:
    keys = set()
    for path in python_sources():
        text = path.read_text(encoding="utf-8")
        keys.update(re.findall(r"setting\(\s*'([a-z_][a-z0-9_.]*)'", text))
        keys.update(re.findall(r"lookup\(\s*config\s*,\s*[\"']([a-z_][a-z0-9_.]*)[\"']", text))
    for path in sorted(LAB.glob("*.ps1")):
        keys.update(re.findall(r"\$labConfig\.([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+)", path.read_text(encoding="utf-8")))
    return keys


def test_example_lists_every_key_the_tools_read() -> None:
    lab_config = load_module("lab_config")
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    keys = configuration_keys()
    assert len(keys) >= 30
    for key in sorted(keys):
        lab_config.lookup(data, key, allow_null=True)


def test_lab_config_lookup_fails_closed() -> None:
    lab_config = load_module("lab_config")
    data = {"a": {"b": 1, "empty": None}}
    assert lab_config.lookup(data, "a.b") == 1
    assert lab_config.lookup(data, "a.empty", allow_null=True) is None
    with pytest.raises(LookupError, match="missing"):
        lab_config.lookup(data, "a.c")
    with pytest.raises(LookupError, match="missing"):
        lab_config.lookup(data, "a.b.c")
    with pytest.raises(LookupError, match="empty"):
        lab_config.lookup(data, "a.empty")


def test_lab_config_location_honours_the_environment(tmp_path, monkeypatch) -> None:
    lab_config = load_module("lab_config")
    target = tmp_path / "lab.json"
    monkeypatch.setenv(lab_config.ENVIRONMENT, str(target))
    assert lab_config.location() == target


def test_lab_config_mac_forms() -> None:
    lab_config = load_module("lab_config")
    # Synthetic octets joined at run time, so the source holds no literal hardware address.
    octets = ["02", "00", "00", "00", "00", "0a"]
    assert lab_config.mac("-".join(octets).upper()) == ":".join(octets)
    assert lab_config.mac(":".join(octets), form="vbox") == "".join(octets).upper()
    for bad in ("-".join(octets[:5]), "-".join(octets[:5] + ["0g"])):
        with pytest.raises(ValueError):
            lab_config.mac(bad)
    with pytest.raises(ValueError):
        lab_config.mac("".join(octets), form="other")


def test_lab_config_fill_and_quote() -> None:
    lab_config = load_module("lab_config")
    assert lab_config.ps_quote("it's") == "'it''s'"
    assert lab_config.fill("x=@NAME@", NAME="a'b") == "x=" + repr("a'b")
    assert lab_config.fill("$h=@H@", quote=lab_config.ps_quote, H="LAB") == "$h='LAB'"
    assert lab_config.fill("[@N@]", quote=str, N="1, 2") == "[1, 2]"
    with pytest.raises(KeyError):
        lab_config.fill("nothing here", NAME="x")


def test_egress_proxy_policy_without_network() -> None:
    proxy = load_module("lab_egress_proxy")
    assert proxy.CLIENT is None
    for host in ("auth.openai.com", "chatgpt.com", "cdn.oaistatic.com", "challenges.cloudflare.com"):
        assert proxy.allowed_host(host)
    for host in ("chatgpt.com.attacker.invalid", "notopenai.com", "127.0.0.1", "example.com", "openai.com@127.0.0.1"):
        assert not proxy.allowed_host(host)
    for address in ("127.0.0.1", "::1", *proxy.RESERVED_SAMPLES, *proxy.DOCUMENTATION_SAMPLES):
        assert not proxy.global_address(address)
    assert len(proxy.RESERVED_SAMPLES) == 6
    assert not any(ipaddress.ip_address(x).is_global for x in proxy.RESERVED_SAMPLES)


def test_efficiency_prompt_and_command_digest() -> None:
    namespace = functions_from(LAB / "windows_efficiency_smoke.py", {"prompt", "command_digest"},
                               {"json": json, "hashlib": hashlib})
    prompt, command_digest = namespace["prompt"], namespace["command_digest"]
    case = {"task_id": "T-1", "task": "find", "corpus": [{"key": "k"}], "capsule": {"fact": "f"}}
    on, off = prompt(case, "ON"), prompt(case, "OFF")
    assert "TASK_AND_COMMON_DOCUMENTS" in on and '"fact": "f"' in on
    assert "Not provided for this experimental arm." in off and '"fact"' not in off
    files = prompt({**case, "kind": "files"}, "OFF")
    assert '"documents_directory": "documents"' in files and '"corpus"' not in files
    assert command_digest({"command": "dir"}) == hashlib.sha256(b"dir").hexdigest()
    assert command_digest({"command": ["a", "b"]}) == hashlib.sha256(json.dumps(["a", "b"]).encode()).hexdigest()
    assert command_digest({"command": ""}) is None and command_digest({"command": [1]}) is None
