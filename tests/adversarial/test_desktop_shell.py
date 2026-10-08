"""The desktop shell's security posture, pinned so it cannot drift (ADR-0008).

Each of these is a decision that is easy to undo by accident: one more permission in
a capability file, one remote origin in the CSP, a Tauri plugin added for
convenience, an npm install script, the WebView's profile left in AppData. Each is
asserted structurally here, against the files that ship, so loosening any of them
is a red test rather than a quiet diff.

What runs is tested elsewhere: the Job Object and the allowlist in the shell's own
Rust tests (`apps/desktop/src-tauri`), the window in Vitest (`apps/desktop/src`).
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.adversarial

DESKTOP = Path(__file__).resolve().parents[2] / "apps" / "desktop"
TAURI = DESKTOP / "src-tauri"


def conf() -> dict[str, object]:
    data: dict[str, object] = json.loads((TAURI / "tauri.conf.json").read_text("utf-8"))
    return data


def csp() -> dict[str, list[str]]:
    app = conf()["app"]
    assert isinstance(app, dict)
    policy = app["security"]["csp"]
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        words = part.split()
        if words:
            directives[words[0]] = words[1:]
    return directives


def test_the_window_is_granted_exactly_two_commands() -> None:
    capability = json.loads((TAURI / "capabilities" / "main.json").read_text("utf-8"))
    assert capability["windows"] == ["main"]
    assert sorted(capability["permissions"]) == ["allow-bridge-call", "allow-bridge-info"]


def test_commands_are_deny_by_default() -> None:
    """build.rs declares an app manifest; without it every command is open to every window."""
    build = (TAURI / "build.rs").read_text("utf-8")
    assert "AppManifest::new().commands(" in build
    declared = re.findall(r'"([a-z_]+)"', build.split("commands(", 1)[1].split(")", 1)[0])
    assert sorted(declared) == ["bridge_call", "bridge_info"]
    lib = (TAURI / "src" / "lib.rs").read_text("utf-8")
    handler = lib.split("generate_handler![", 1)[1].split("]", 1)[0]
    assert sorted(h.strip() for h in handler.split(",") if h.strip()) == declared


def test_no_tauri_plugins_widen_the_window() -> None:
    """No shell, fs, http or any other plugin, in Rust or in npm."""
    cargo = tomllib.loads((TAURI / "Cargo.toml").read_text("utf-8"))
    deps = set(cargo.get("dependencies", {}))
    assert not [d for d in deps if d.startswith("tauri-plugin")]
    package = json.loads((DESKTOP / "package.json").read_text("utf-8"))
    every = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    assert not [d for d in every if "plugin-" in d and d.startswith("@tauri-apps/")]


def test_the_csp_allows_nothing_remote() -> None:
    directives = csp()
    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert set(directives["connect-src"]) <= {"ipc:", "http://ipc.localhost"}
    everything = " ".join(word for words in directives.values() for word in words)
    for forbidden in (
        "unsafe-eval",
        "unsafe-inline",
        "https:",
        "http:*",
        "*",
        "data: 'self' https",
    ):
        assert forbidden not in everything.split(), forbidden


def test_the_shell_hides_nothing_from_its_own_csp() -> None:
    app = conf()["app"]
    assert isinstance(app, dict)
    assert app["withGlobalTauri"] is False
    assert app["security"]["freezePrototype"] is True


def test_the_webview_profile_lives_under_var() -> None:
    """LAW 0 section 2. Measured on 2026-10-02: left to itself WebView2 wrote 232 files to
    %LOCALAPPDATA%. The window is built in code so its data directory can be pointed
    inside var/, and the config defines no window that could bypass that."""
    app = conf()["app"]
    assert isinstance(app, dict)
    assert app["windows"] == [], "a window defined in config would get the default profile"
    lib = (TAURI / "src" / "lib.rs").read_text("utf-8")
    assert ".data_directory(" in lib
    assert 'join("var").join("webview")' in lib


def test_npm_install_runs_no_scripts_and_pins_exactly() -> None:
    npmrc = (DESKTOP / ".npmrc").read_text("utf-8")
    assert "ignore-scripts=true" in npmrc
    assert "save-exact=true" in npmrc
    package = json.loads((DESKTOP / "package.json").read_text("utf-8"))
    for name, version in {**package["dependencies"], **package["devDependencies"]}.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{name} is not pinned exactly: {version}"


def test_every_npm_package_is_locked_by_hash() -> None:
    lock = json.loads((DESKTOP / "package-lock.json").read_text("utf-8"))
    packages = {k: v for k, v in lock["packages"].items() if k}
    assert packages, "an empty lockfile locks nothing"
    unhashed = [k for k, v in packages.items() if not v.get("link") and not v.get("integrity")]
    assert unhashed == []


def test_the_kernel_starts_inside_its_job() -> None:
    """The structural half; the behavioural half is job.rs's own tests, which start a
    process and prove it is in the job and dies when the job closes."""
    bridge = (TAURI / "src" / "bridge.rs").read_text("utf-8")
    assert "spawn_confined(&mut cmd, crate::job::Limits::LAW_ZERO)" in bridge
    job = (TAURI / "src" / "job.rs").read_text("utf-8")
    assert "CREATE_SUSPENDED" in job
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in job
    assert job.index("Job::new(limits)?") < job.index("cmd.spawn()?"), "limits before the process"
