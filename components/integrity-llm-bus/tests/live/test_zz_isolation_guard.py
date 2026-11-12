"""Test isolation guard: tests use only this copy of the package and never its default state.

Named test_zz_* so unittest discover runs it last. The audit hook is installed when this
module is imported during discovery, i.e. before any test runs, and only records:
- opens / sqlite connects under this package's state/ or bridge-state/ (default state
  instead of a tempdir; in an installed bus that is the real bus state);
- opens / directory listings under ~/.codex or ~/.claude (real agent homes);
- socket connects to Host Link (127.0.0.1:49481) or any non-loopback address, and
  non-loopback DNS lookups.
Child processes started by tests are not covered; they must pass an explicit --state-dir.
"""
import ast
import os
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
HERE = TESTS.parents[1] / "src" / "integrity_llm_bus" / "resources"
_LOOPBACK = (None, "127.0.0.1", "::1", "localhost", b"127.0.0.1", b"::1", b"localhost")
_events = []


def _norm(value):
    try:
        return os.path.normcase(os.path.realpath(os.fsdecode(value)))
    except (TypeError, ValueError):
        return ""


_STATE_DIRS = tuple(_norm(HERE / d) for d in ("state", "bridge-state"))
_HOME_DIRS = tuple(_norm(Path.home() / d) for d in (".codex", ".claude"))


def _under(path, roots):
    return any(path == d or path.startswith(d + os.sep) for d in roots)


def _audit(event, args):
    if (event in ("open", "sqlite3.connect", "os.scandir", "os.listdir") and args
            and isinstance(args[0], (str, bytes, os.PathLike))):
        path = _norm(args[0])
        if (event in ("open", "sqlite3.connect") and _under(path, _STATE_DIRS)) or _under(path, _HOME_DIRS):
            _events.append(f"{event} {path}")
    elif event == "socket.getaddrinfo" and args and args[0] not in _LOOPBACK:
        _events.append(f"{event} {args[0]!r}")
    elif event == "socket.connect" and len(args) > 1 and isinstance(args[1], tuple) and len(args[1]) >= 2:
        host, port = args[1][0], args[1][1]
        if host not in ("127.0.0.1", "::1", "localhost") or port == 49481:
            _events.append(f"{event} {host}:{port}")


sys.addaudithook(_audit)


def _local_modules():
    return {p.stem for p in HERE.glob("*.py")}


class IsolationGuard(unittest.TestCase):
    def test_package_modules_imported_from_this_folder(self):
        wrong = {}
        for name in sorted(_local_modules()):
            module = sys.modules.get(name)
            origin = getattr(module, "__file__", None)
            if origin and Path(origin).resolve().parent != HERE:
                wrong[name] = origin
        self.assertEqual(wrong, {}, "tests imported bus modules from another folder (e.g. an installed bus)")

    def test_no_hardcoded_package_paths_in_tests(self):
        problems = []
        for path in sorted(TESTS.glob("test_*.py")):
            source = path.read_text(encoding="utf-8-sig")  # some test files carry a BOM
            for node in ast.walk(ast.parse(source)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("insert", "append")
                        and ast.unparse(node.func.value) == "sys.path"
                        and any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                                for a in node.args for n in ast.walk(a))):
                    problems.append(f"{path.name}:{node.lineno}: sys.path entry from a string literal")
        self.assertEqual(problems, [])

    def test_no_default_state_or_external_network_during_run(self):
        self.assertEqual(sorted(set(_events)), [],
                         "a test touched the package default state/, a real agent home or a non-loopback/Host Link endpoint")


if __name__ == "__main__":
    unittest.main()
