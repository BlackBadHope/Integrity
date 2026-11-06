"""User-made JSON and TOML may start with a UTF-8 BOM.

Windows PowerShell 5.1 (`Set-Content -Encoding utf8`) and Notepad write one. A
fresh Windows install was refused with "Unexpected UTF-8 BOM" before this.
"""
import json

from integrity_client_memory import doctor, native_install

BOM = b"\xef\xbb\xbf"


def test_native_install_reads_json_with_bom(tmp_path):
    path = tmp_path / "bindings.json"
    path.write_bytes(BOM + json.dumps({"seed_namespace": "seed://project/x"}).encode("utf-8"))
    assert native_install.read_json(path) == {"seed_namespace": "seed://project/x"}
    plain = tmp_path / "plain.json"
    plain.write_text('{"a": 1}', encoding="utf-8")
    assert native_install.read_json(plain) == {"a": 1}


def test_doctor_reads_settings_with_bom(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_bytes(BOM + b'{"hooks": {}}')
    assert doctor._read_json(settings) == {"hooks": {}}
