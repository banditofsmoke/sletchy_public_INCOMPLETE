"""The `sletchy` command.

Small on purpose: inspect state, and stop things. Running agents is the desktop
shell's job (Wave 6).

**Nothing here is re-exported under a name that collides with a submodule.**
`from .main import main` would rebind `sletchy.cli.main` from the *module* to the
*function*, so `monkeypatch.setattr("sletchy.cli.main.X", ...)` - and any other
attribute access through the module path - would fail with a confusing
"'function' object has no attribute". The aliases keep both reachable.

The console entry point in pyproject.toml targets `sletchy.cli.main:main`, which
resolves through the module and is unaffected by the aliasing here.
"""

from sletchy.cli.main import build_parser
from sletchy.cli.main import main as run_cli
from sletchy.cli.panic import PanicReport
from sletchy.cli.panic import panic as run_panic

__all__ = ["PanicReport", "build_parser", "run_cli", "run_panic"]
