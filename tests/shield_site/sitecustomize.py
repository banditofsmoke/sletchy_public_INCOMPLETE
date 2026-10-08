"""The host shield, in every Python process a test starts (L016).

`tests/conftest.py` puts this folder first on `PYTHONPATH` for the run, so a child
Python imports this file before its own code. The session's shield guards the pytest
process only. Without this, a test that runs Sletchy in a second process takes it
outside every guard, which is how the window's end-to-end test ran a real panic
against the operator's firewall.

`hostshield.py` is loaded by its path, so nothing is added to the child's `sys.path`.

A process started with `-I`, or with the Kernel's stripped environment (every
sandbox), does not read `PYTHONPATH` and is not shielded here. The quarantine run and
the sandboxes are contained by their own means.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_log = os.environ.get("SLETCHY_TEST_SHIELD_LOG")
if _log:
    _spec = importlib.util.spec_from_file_location(
        "sletchy_test_hostshield", Path(__file__).resolve().parent.parent / "hostshield.py"
    )
    assert _spec is not None and _spec.loader is not None
    _module = importlib.util.module_from_spec(_spec)
    # A dataclass looks its module up while it is being built.
    sys.modules[_spec.name] = _module
    _spec.loader.exec_module(_module)
    _module.install_in_child(Path(_log))
