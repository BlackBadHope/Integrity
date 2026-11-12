"""Load the shared synthetic configuration once per test process (see tests/_bus_setup.py)."""
import importlib.util
from pathlib import Path
import sys

if "_integrity_llm_bus_test_setup" not in sys.modules:
    _spec = importlib.util.spec_from_file_location("_integrity_llm_bus_test_setup",
                                                   Path(__file__).resolve().parents[1] / "_bus_setup.py")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _module
    _spec.loader.exec_module(_module)
