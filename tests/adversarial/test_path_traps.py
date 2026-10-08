"""Every Windows trick that defeats a naive path check, as a test (#68).

fsguard turns a path Sletchy was handed into a path provably inside a declared root, or a
refusal. Each section below is one way the naive version - compare the strings, or
normalise them lexically - is wrong on Windows. Every test that touches the disk does so
inside pytest's temporary folder; the junction and short-name tests create their own
folders there and nothing else.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
import unicodedata
from pathlib import Path

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.warden.fsguard import (
    REFUSED_ACTION,
    RESERVED_NAMES,
    FsGuard,
    PathRefused,
    Root,
    check_text,
    confine,
    ensure_room,
    within,
)

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="a Windows filesystem behaviour")


@pytest.fixture
def root(tmp_path: Path) -> Root:
    folder = tmp_path / "root"
    folder.mkdir()
    return Root.declare("workspace", folder, max_bytes=10_000, max_files=5)


def junction(target: Path, link: Path) -> None:
    """A directory junction, which needs no privilege. Windows only; reached by name for mypy."""
    winapi = importlib.import_module("_winapi")
    winapi.CreateJunction(str(target), str(link))


def refused(root: Root, given: str) -> str:
    with pytest.raises(PathRefused) as caught:
        confine(root, given)
    return caught.value.rule


# ── the basics: resolve, then compare by components ──────────────────────────


def test_a_relative_path_is_taken_relative_to_the_root_not_the_current_folder(root: Root) -> None:
    assert confine(root, "sub/file.txt") == root.path / "sub" / "file.txt"


def test_an_absolute_path_inside_the_root_is_accepted(root: Root) -> None:
    inside = root.path / "a" / "b.txt"
    assert confine(root, str(inside)) == inside


@pytest.mark.parametrize(
    "given", ["../outside.txt", "sub/../../outside.txt", "./../x", "a/./../../x"]
)
def test_traversal_out_of_the_root_is_refused(root: Root, given: str) -> None:
    assert refused(root, given) == "outside_root"


def test_a_sibling_whose_name_starts_with_the_roots_is_not_inside_it(root: Root) -> None:
    """`C:\\var\\sletchy-evil` must not pass as inside `C:\\var\\sletchy`: components, not prefixes."""
    evil = root.path.parent / (root.path.name + "-evil") / "x.txt"
    assert str(evil).startswith(str(root.path))
    assert refused(root, str(evil)) == "outside_root"


@windows_only
def test_comparison_ignores_case_on_windows(root: Root) -> None:
    upper = Path(str(root.path).upper()) / "x.txt"
    assert within(confine(root, str(upper)), root.path)


def test_a_refused_path_is_never_clamped_into_the_root(root: Root) -> None:
    """No repair mode: the escape raises, and nothing is written anywhere."""
    with pytest.raises(PathRefused):
        confine(root, "../../escaped.txt")
    assert not (root.path / "escaped.txt").exists()
    assert list(root.path.iterdir()) == []


# ── 8.3 short names ──────────────────────────────────────────────────────────


def _short_name(path: Path) -> str:
    # Reached by name: the Windows-only attributes do not exist where CI type-checks on Linux.
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
    kernel32.GetShortPathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.GetShortPathNameW.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(1024)
    if not kernel32.GetShortPathNameW(str(path), buffer, 1024):
        return str(path)
    return buffer.value


@windows_only
def test_a_short_name_resolves_to_the_tree_it_really_names(tmp_path: Path) -> None:
    """`PROGRA~1` is `Program Files`: compare the short spelling and the answer is wrong."""
    root_folder = tmp_path / "A Long Root Folder Name"
    outside = tmp_path / "A Long Outside Folder Name"
    root_folder.mkdir()
    outside.mkdir()
    short_outside = _short_name(outside)
    if short_outside == str(outside):
        pytest.skip("this volume does not create 8.3 short names; nothing to resolve")
    root = Root.declare("workspace", root_folder, max_bytes=1, max_files=1)

    assert refused(root, short_outside + "\\x.txt") == "outside_root"
    short_root = _short_name(root_folder)
    assert confine(root, short_root + "\\x.txt") == root.path / "x.txt"


# ── alternate data streams ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given", ["file.txt:hidden", "dir::$DATA", "f.txt:$DATA", "a/b.txt:stream:$DATA"]
)
def test_an_alternate_data_stream_is_refused(root: Root, given: str) -> None:
    assert refused(root, given) == "stream"


def test_a_stream_after_an_absolute_path_is_refused(root: Root) -> None:
    assert refused(root, str(root.path / "f.txt") + ":hidden") == "stream"


# ── device names ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given",
    [
        "CON",
        "nul",
        "Aux.txt",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt0",
        "COM\u00b9",
        "CONIN$",
        "sub/NUL.tar.gz",
        "PRN.x",
    ],
)
def test_a_reserved_device_name_is_refused_anywhere_with_any_extension(
    root: Root, given: str
) -> None:
    assert refused(root, given) == "device_name"


@pytest.mark.parametrize(
    "given", ["console.txt", "nullify.py", "auxiliary", "COM10", "lpt", "con-artist.md"]
)
def test_names_that_only_look_like_devices_are_allowed(root: Root, given: str) -> None:
    """Negative control: a check that refuses ordinary names gets switched off."""
    assert confine(root, given) == root.path / given


def test_every_reserved_name_is_on_the_list() -> None:
    expected = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    for prefix in ("COM", "LPT"):
        expected |= {f"{prefix}{d}" for d in "0123456789\u00b9\u00b2\u00b3"}
    assert expected == RESERVED_NAMES


# ── device paths ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given",
    [
        r"\\.\C:\x",
        r"\\?\C:\x",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
        r"\\.\PhysicalDrive0",
        r"\??\C:\x",
        "//?/C:/x",
        "//./pipe/name",
    ],
)
def test_a_device_or_raw_path_is_refused(root: Root, given: str) -> None:
    assert refused(root, given) == "device_path"


# ── shares ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given", [r"\\server\share\x", r"\\127.0.0.1\C$\x", "//localhost/c$/x", r"\\wsl$\Ubuntu\home"]
)
def test_a_network_or_administrative_share_is_refused(root: Root, given: str) -> None:
    assert refused(root, given) == "share"


# ── drive-relative paths ─────────────────────────────────────────────────────


@pytest.mark.parametrize("given", ["C:foo", "C:", "D:..\\x"])
def test_a_drive_relative_path_is_refused(root: Root, given: str) -> None:
    """`C:foo` is "foo in C:'s current folder", wherever it is read."""
    assert refused(root, given) == "drive_relative"


@windows_only
@pytest.mark.parametrize("given", [r"\foo", "/foo/bar"])
def test_a_driveless_rooted_path_is_refused_on_windows(root: Root, given: str) -> None:
    """`\\foo` is "foo at the current drive's root": which drive depends on where you are."""
    assert refused(root, given) == "drive_relative"


def test_a_posix_absolute_path_is_not_mistaken_for_one(root: Root) -> None:
    """On a POSIX host, `/tmp/x` is an ordinary absolute path (Linux CI caught this)."""
    if sys.platform == "win32":
        pytest.skip("POSIX paths only mean this off Windows")
    inside = root.path / "x.txt"
    assert confine(root, str(inside)) == inside


# ── trailing dots and spaces ─────────────────────────────────────────────────


@pytest.mark.parametrize("given", ["evil.txt.", "evil.txt ", "dir./x", "dir /x", "x...", "y . "])
def test_a_trailing_dot_or_space_is_refused(root: Root, given: str) -> None:
    """Windows strips them, so `evil.txt.` opens `evil.txt` while comparing as something else."""
    assert refused(root, given) == "trailing_dot_or_space"


# ── long paths ───────────────────────────────────────────────────────────────


def test_a_long_path_inside_the_root_is_judged_like_any_other(root: Root) -> None:
    deep = "/".join(["d" * 50] * 8) + "/file.txt"
    result = confine(root, deep)
    assert len(str(result)) > 260
    assert within(result, root.path)


def test_a_long_path_that_escapes_is_still_refused(root: Root) -> None:
    deep = "/".join(["d" * 50] * 6) + "/" + "/".join([".."] * 8) + "/escaped.txt"
    assert refused(root, deep) == "outside_root"


def test_the_long_path_prefix_that_disables_normalisation_is_refused(root: Root) -> None:
    assert refused(root, "\\\\?\\" + str(root.path / "x.txt")) == "device_path"


# ── junctions and symbolic links ─────────────────────────────────────────────


@windows_only
def test_a_junction_inside_the_root_that_points_out_of_it_is_refused(tmp_path: Path) -> None:
    root_folder = tmp_path / "root"
    outside = tmp_path / "outside"
    root_folder.mkdir()
    outside.mkdir()
    junction(outside, root_folder / "door")
    root = Root.declare("workspace", root_folder, max_bytes=1, max_files=1)

    assert refused(root, "door/secrets.txt") == "outside_root"
    assert refused(root, str(root_folder / "door" / "x")) == "outside_root"


@windows_only
def test_a_junction_that_stays_inside_the_root_is_allowed(tmp_path: Path) -> None:
    """Positive control: resolution follows the link; it does not refuse links as such."""
    root_folder = tmp_path / "root"
    (root_folder / "real").mkdir(parents=True)
    junction(root_folder / "real", root_folder / "alias")
    root = Root.declare("workspace", root_folder, max_bytes=1, max_files=1)

    assert confine(root, "alias/x.txt") == root.path / "real" / "x.txt"


def test_a_symbolic_link_out_of_the_root_is_refused(tmp_path: Path) -> None:
    root_folder = tmp_path / "root"
    outside = tmp_path / "outside"
    root_folder.mkdir()
    outside.mkdir()
    try:
        (root_folder / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating a symbolic link needs a privilege this account does not have")
    root = Root.declare("workspace", root_folder, max_bytes=1, max_files=1)
    assert refused(root, "link/x.txt") == "outside_root"


def test_a_root_declared_through_a_link_is_its_real_folder(tmp_path: Path) -> None:
    """The root is canonical before anything is compared with it."""
    real = tmp_path / "real"
    real.mkdir()
    try:
        (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("creating a symbolic link needs a privilege this account does not have")
    assert Root.declare("w", tmp_path / "alias", max_bytes=1, max_files=1).path == real.resolve()


# ── unicode ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given",
    [
        "evil\u202etxt.exe",
        "a\u200db.txt",
        "x\u0000.txt",
        "tab\there",
        "bom\ufeff.txt",
        "line\nbreak",
    ],
)
def test_an_invisible_or_control_character_is_refused(root: Root, given: str) -> None:
    """A right-to-left override shows `evilexe.txt`; a zero-width joiner hides in plain sight."""
    assert refused(root, given) == "invisible_character"


def test_a_homoglyph_of_the_roots_name_is_a_different_folder(root: Root) -> None:
    """Cyrillic `\u0430` looks like Latin `a`. It is another name, so another folder: outside."""
    name = root.path.name
    lookalike = name.replace("o", "\u043e")
    assert lookalike != name
    assert refused(root, str(root.path.parent / lookalike / "x.txt")) == "outside_root"


def test_a_differently_normalised_name_is_compared_as_written(tmp_path: Path) -> None:
    """NTFS does not normalise, so NFC and NFD spellings name two folders. Neither is merged."""
    nfc = unicodedata.normalize("NFC", "caf\u00e9")
    nfd = unicodedata.normalize("NFD", "caf\u00e9")
    assert nfc != nfd
    (tmp_path / nfc).mkdir()
    root = Root.declare("w", tmp_path / nfc, max_bytes=1, max_files=1)
    if (tmp_path / nfd).exists():
        pytest.skip("this filesystem normalises names, so both spellings are one folder")
    assert refused(root, str(tmp_path / nfd / "x.txt")) == "outside_root"


def test_ordinary_unicode_names_are_allowed(root: Root) -> None:
    for name in ("caf\u00e9.txt", "\u65e5\u672c\u8a9e.md", "na\u00efve plan.txt", "\U0001f600.png"):
        assert confine(root, name) == root.path / name


# ── nothing declared, nothing allowed; every refusal on the record ───────────


def _guard(roots: list[Root], tmp_path: Path) -> tuple[FsGuard, Ledger]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    return FsGuard(roots, ledger=ledger, actor_id="fsguard_test"), ledger


def test_with_no_root_declared_every_path_is_refused(tmp_path: Path) -> None:
    guard, ledger = _guard([], tmp_path)
    for given in ("x.txt", str(tmp_path / "x.txt"), "."):
        with pytest.raises(PathRefused) as caught:
            guard.confine("workspace", given)
        assert caught.value.rule == "no_root"
    assert [e.verdict.rule_id for e in ledger.entries()] == ["no_root"] * 3


def test_every_refusal_is_recorded_before_it_is_raised_and_names_its_rule(
    root: Root, tmp_path: Path
) -> None:
    guard, ledger = _guard([root], tmp_path)
    attempts = {
        "../x": "outside_root",
        "NUL": "device_name",
        "f.txt:s": "stream",
        "C:x": "drive_relative",
        r"\\srv\s\x": "share",
    }
    for given in attempts:
        with pytest.raises(PathRefused):
            guard.confine("workspace", given)
    entries = list(ledger.entries())
    assert [e.verdict.rule_id for e in entries] == list(attempts.values())
    assert all(e.action == REFUSED_ACTION for e in entries)
    assert all(e.verdict.decision.value == "deny" for e in entries)


def test_a_path_that_passes_is_not_recorded_here(root: Root, tmp_path: Path) -> None:
    """The action that uses it is recorded, not the check: allowed checks would flood the ledger."""
    guard, ledger = _guard([root], tmp_path)
    guard.confine("workspace", "fine.txt")
    assert list(ledger.entries()) == []


def test_a_hostile_path_is_recorded_bounded(root: Root, tmp_path: Path) -> None:
    guard, ledger = _guard([root], tmp_path)
    with pytest.raises(PathRefused):
        guard.confine("workspace", "../" + "x" * 5000)
    (entry,) = ledger.entries()
    assert len(entry.subject.identifier) <= 200


# ── quotas, checked before a write ───────────────────────────────────────────


def test_a_write_past_the_byte_ceiling_is_refused_before_it_happens(root: Root) -> None:
    (root.path / "a.bin").write_bytes(b"x" * 9_000)
    ensure_room(root, 1_000)
    with pytest.raises(PathRefused) as caught:
        ensure_room(root, 1_001)
    assert caught.value.rule == "quota_bytes"


def test_a_write_past_the_file_ceiling_is_refused_before_it_happens(root: Root) -> None:
    for i in range(5):
        (root.path / f"f{i}").write_bytes(b"")
    with pytest.raises(PathRefused) as caught:
        ensure_room(root, 0)
    assert caught.value.rule == "quota_files"


@windows_only
def test_the_quota_does_not_follow_a_junction_out_of_the_root(tmp_path: Path) -> None:
    """A link to a huge folder elsewhere must not count against, or hide, this root's usage."""
    root_folder = tmp_path / "root"
    outside = tmp_path / "outside"
    root_folder.mkdir()
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"x" * 50_000)
    junction(outside, root_folder / "door")
    root = Root.declare("workspace", root_folder, max_bytes=10_000, max_files=5)
    ensure_room(root, 1_000)


# ── declaring a root ─────────────────────────────────────────────────────────


def test_a_root_must_be_an_existing_folder(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        Root.declare("w", tmp_path / "missing", max_bytes=1, max_files=1)
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        Root.declare("w", tmp_path / "file", max_bytes=1, max_files=1)


@pytest.mark.parametrize(
    "given", ["notes.txt", "a.b.c", "sub/dir/file", "-dash", "name with spaces.txt"]
)
def test_ordinary_paths_pass_the_text_check(given: str) -> None:
    check_text(given)


def test_an_empty_path_is_refused(root: Root) -> None:
    assert refused(root, "") == "empty"
    assert refused(root, "   ") == "empty"


def test_os_pathlike_inputs_are_checked_the_same(root: Root) -> None:
    assert confine(root, Path("sub") / "x.txt") == root.path / "sub" / "x.txt"
    with pytest.raises(PathRefused):
        confine(root, Path("..") / "x.txt")
    assert os.fspath(Path("a")) == "a"
