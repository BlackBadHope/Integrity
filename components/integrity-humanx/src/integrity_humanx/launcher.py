"""Launch one HumanX resource process after explicit configuration admission."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from .configuration import COMPONENT, ENVIRONMENT, ConfigurationError, read_config

HERE = Path(__file__).resolve().parent


def resource_catalog():
    return json.loads((HERE / "resources.json").read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--list", action="store_true", help="List source entrypoints without importing them")
    parser.add_argument("--preflight", action="store_true", help="Validate configuration only; no process/network/state")
    parser.add_argument("entrypoint", nargs="?")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    catalog = resource_catalog()
    if args.list:
        print(json.dumps({"component": COMPONENT, "entrypoints": sorted(catalog)}))
        return 0
    try:
        read_config(args.config)
        if args.preflight:
            print(json.dumps({"component": COMPONENT, "status": "configuration-header-valid", "runtime_bindings_verified": False,
                              "process_started": False, "network_used": False}))
            return 0
        if args.entrypoint not in catalog:
            raise ConfigurationError("choose an explicit entrypoint from --list")
        entry = catalog[args.entrypoint]
        script = HERE / entry["path"]
        if script.is_symlink() or not script.is_file() or not script.resolve().is_relative_to(HERE):
            raise ConfigurationError("resource integrity failure")
        environment = dict(os.environ)
        environment[ENVIRONMENT] = str(Path(args.config or environment[ENVIRONMENT]).resolve())
        # A fresh process keeps the flat module names of the resources (rings_screen, dlinkcli, ...) apart.
        command = [sys.executable, "-B", str(script), *args.arguments]
        return subprocess.call(command, env=environment)
    except ConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
