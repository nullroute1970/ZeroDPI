#!/usr/bin/env python3
"""
build.py – Build ZeroDPI for the current platform, Windows, Linux, or Termux.

Usage:
    python build.py [--platform linux|windows|termux|all]
                   [--windivert-version <ver>] [--toolchain <toolchain>]
                   [--msys2-path <path>]
                   [--termux-arch all|armv7|armv8|<arch>] [--android-ndk <path>]

What it does
------------
Linux:
  1. Checks that libnetfilter-queue-dev is installed (offers to install it).
  2. Runs `cargo build --workspace --release`.
  3. Copies the resulting binary + config.toml + sni_list.txt + ip_list.txt +
     README.md to dist/linux/.

Windows:
  1. Downloads/verifies the repo-local windivert/ folder and sets WINDIVERT_PATH.
  2. Runs `cargo +<toolchain> build --workspace --release` (default toolchain:
     stable-x86_64-pc-windows-gnu). Pass --toolchain="" to use the workspace
     default toolchain instead.
  3. Copies zerodpi.exe + WinDivert.dll + WinDivert64.sys + config.toml +
     sni_list.txt + ip_list.txt + README.md to dist/windows/.

Termux:
  1. Finds the Android NDK from --android-ndk or ANDROID_NDK_HOME.
  2. Configures Cargo to use the selected NDK clang linker.
  3. Runs `cargo build --workspace --release --target <android-target>`.
  4. Copies zerodpi + config.toml + sni_list.txt + ip_list.txt + README.md
     to dist/termux/<arch>/. The default `all` builds Android ARMv7 and ARMv8.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WINDIVERT_DEFAULT_VERSION = "2.2.2"
WINDIVERT_VERSION_FILE = ".version"
WINDIVERT_REQUIRED_FILES = ("WinDivert.dll", "WinDivert.lib", "WinDivert64.sys")
WINDIVERT_RELEASE_URL = "https://github.com/basil00/WinDivert/releases/download/v{version}/WinDivert-{version}-A.zip"
# On Windows this project targets the GNU toolchain by default.
WINDOWS_DEFAULT_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"
# Default MSYS2 installation path; its mingw64/bin is prepended to PATH when
# building with a GNU toolchain so that gcc, dlltool, ld, etc. are reachable.
WINDOWS_DEFAULT_MSYS2_PATH = r"C:\msys64"
LINUX_TARGET = "x86_64-unknown-linux-gnu"
LINUX_CROSS_TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
]
DEFAULT_LINUX_TARGET = "x86_64-unknown-linux-gnu"

LINUX_TARGET_ALIASES = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "x86_64-gnu": "x86_64-unknown-linux-gnu",
    "amd64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
    "aarch64-gnu": "aarch64-unknown-linux-gnu",
    "arm64": "aarch64-unknown-linux-gnu",
    "x86_64-musl": "x86_64-unknown-linux-musl",
    "aarch64-musl": "aarch64-unknown-linux-musl",
}
ANDROID_DEFAULT_API_LEVEL = 23
TERMUX_DEFAULT_ARCH = "all"
ANDROID_NDK_DEFAULT_VERSION = "r27"
TERMUX_ARM_ARCHES = ("armv7", "armv8")
TERMUX_RUST_TARGETS = {
    "armv7": "armv7-linux-androideabi",
    "armv8": "aarch64-linux-android",
    "aarch64": "aarch64-linux-android",
    "arm64": "aarch64-linux-android",
    "arm": "armv7-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "i686": "i686-linux-android",
}
TERMUX_CLANG_TARGETS = {
    "armv7": "armv7a-linux-androideabi",
    "armv8": "aarch64-linux-android",
    "aarch64": "aarch64-linux-android",
    "arm64": "aarch64-linux-android",
    "arm": "armv7a-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "i686": "i686-linux-android",
}
TERMUX_ARCH_CHOICES = ("all",) + tuple(sorted(TERMUX_RUST_TARGETS))
REPO_ROOT = Path(__file__).resolve().parent
CARGO_RELEASE_DIR = REPO_ROOT / "target" / "release"
COMMON_DIST_FILES = ("config.toml", "sni_list.txt", "ip_list.txt", "README.md")
LINUX_DIST_FILES = ("install-systemd.sh",)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command, streaming output to the terminal."""
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    merged_env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, env=merged_env, check=check)


def die(msg: str) -> None:
    print(f"\nERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def copy_required_file(src: Path, dest: Path) -> None:
    if not src.exists():
        die(f"Expected file not found: {src}")
    shutil.copy2(src, dest)


def copy_common_dist_files(dist_dir: Path) -> None:
    for filename in COMMON_DIST_FILES:
        copy_required_file(REPO_ROOT / filename, dist_dir / filename)


def copy_linux_dist_files(dist_dir: Path) -> None:
    for filename in LINUX_DIST_FILES:
        dest = dist_dir / filename
        copy_required_file(REPO_ROOT / filename, dest)
        dest.chmod(0o755)


def print_dist_contents(dist_dir: Path) -> None:
    print(f"\n=== Build complete. Artifacts in: {dist_dir} ===")
    for f in sorted(dist_dir.iterdir()):
        print(f"  {f}")


def confirm_or_die(prompt: str) -> None:
    """Ask for confirmation; exit if denied."""
    try:
        answer = input(f"{prompt} [Y/n]: ").strip().lower()
    except EOFError:
        answer = "n"
    if answer not in ("", "y", "yes"):
        die("Aborted by user.")


def msys2_pacman_install(msys2_path: str, packages: list[str]) -> None:
    """Install packages via MSYS2 pacman inside the MSYS2 environment."""
    bash = Path(msys2_path) / "usr" / "bin" / "bash.exe"
    if not bash.is_file():
        die(
            f"MSYS2 bash not found at {bash}.\n"
            "Install MSYS2 from https://www.msys2.org/ or verify --msys2-path."
        )
    pkg_str = " ".join(packages)
    print(f"\nInstalling MSYS2 packages: {pkg_str}")
    env = {**os.environ, "MSYSTEM": "MINGW64", "CHERE_INVOKING": "1"}
    run([str(bash), "--login", "-c", f"pacman -S --noconfirm {pkg_str}"], env=env)


def android_ndk_download_host_tag() -> str:
    """Return the Android NDK download host tag for the current platform."""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Linux":
        return "linux"
    if system == "Darwin":
        machine = platform.machine().lower()
        return "darwin-arm64" if machine in ("arm64", "aarch64") else "darwin"
    die(f"Unsupported host platform: {system}")


def download_android_ndk(ndk_version: str) -> Path:
    """Download and extract the Android NDK, returning the NDK root path."""
    host_tag = android_ndk_download_host_tag()
    url = (
        f"https://dl.google.com/android/repository/"
        f"android-ndk-{ndk_version}-{host_tag}.zip"
    )
    print(f"\nDownloading Android NDK {ndk_version} from:\n  {url}")

    dest = REPO_ROOT / ".ndk"
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        urllib.request.urlretrieve(url, tmp_path)
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp_path, "r") as zf:
            zf.extractall(dest)
        ndk_dirs = [p for p in dest.iterdir() if p.is_dir() and p.name.startswith("android-ndk-")]
        if not ndk_dirs:
            die("Failed to find extracted Android NDK directory.")
        ndk_path = ndk_dirs[0]
        print(f"Android NDK extracted to: {ndk_path}")
        return ndk_path
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Linux build
# ---------------------------------------------------------------------------

def check_nfqueue_dev() -> bool:
    """Return True if libnetfilter-queue-dev headers are present."""
    result = subprocess.run(
        ["dpkg", "-s", "libnetfilter-queue-dev"],
        capture_output=True,
    )
    return result.returncode == 0


def build_linux() -> None:
    print("=== Building ZeroDPI for Linux ===")

    # Check libnetfilter-queue-dev
    if not check_nfqueue_dev():
        print("libnetfilter-queue-dev is not installed.")
        answer = input("Install it now with apt-get? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            run(["sudo", "apt-get", "update"])
            run(["sudo", "apt-get", "install", "-y", "libnetfilter-queue-dev"])
        else:
            die("libnetfilter-queue-dev is required. Aborting.")

    # Cargo build
    run(["cargo", "build", "--workspace", "--release"], env={"CARGO_TERM_COLOR": "always"})

    # Copy artifacts
    dist_dir = REPO_ROOT / "dist" / "linux"
    dist_dir.mkdir(parents=True, exist_ok=True)

    binary = CARGO_RELEASE_DIR / "zerodpi"
    if not binary.exists():
        die(f"Expected binary not found: {binary}")

    copy_required_file(binary, dist_dir / "zerodpi")
    copy_common_dist_files(dist_dir)
    copy_linux_dist_files(dist_dir)

    print_dist_contents(dist_dir)


# ---------------------------------------------------------------------------
# Linux cross-compilation from Windows (via cargo-zigbuild)
# ---------------------------------------------------------------------------

def resolve_linux_targets(target_arg: str) -> list[str]:
    """Resolve the --linux-target argument to a list of Rust target triples."""
    if target_arg == "all":
        return list(LINUX_CROSS_TARGETS)
    if target_arg in LINUX_TARGET_ALIASES:
        return [LINUX_TARGET_ALIASES[target_arg]]
    if target_arg in LINUX_CROSS_TARGETS:
        return [target_arg]

    av = ", ".join(LINUX_CROSS_TARGETS)
    aliases = ", ".join(sorted(LINUX_TARGET_ALIASES))
    die(
        f"Unknown Linux target: {target_arg}.\n"
        f"  Available targets: all, {av}\n"
        f"  Supported aliases: {aliases}"
    )


def ensure_rustup_targets(targets: list[str]) -> None:
    """Install Rust targets if not already present."""
    installed = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True, text=True,
    ).stdout
    for target in targets:
        if target not in installed.splitlines():
            print(f"\nInstalling Rust target: {target}")
            run(["rustup", "target", "add", target])


def _find_zig_path(msys2_path: str | None) -> Path | None:
    """Locate the zig binary, searching PATH and MSYS2 directories."""
    which = shutil.which("zig")
    if which:
        return Path(which)
    if platform.system() == "Windows" and msys2_path:
        for sub in ("clang64", "mingw64", "ucrt64"):
            candidate = Path(msys2_path) / sub / "bin" / "zig.exe"
            if candidate.is_file():
                return candidate
    return None


def _check_zig_ar_works(zig_path: Path) -> bool:
    """Check if zig's ar subcommand can create archives (broken in 0.17.0-dev)."""
    tmp_dir = REPO_ROOT / ".zig_ar_test"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    test_obj = tmp_dir / "test.o"
    test_archive = tmp_dir / "test.a"
    try:
        if not test_obj.exists():
            subprocess.run(
                [str(zig_path), "cc", "-x", "c", "-c", "-o", str(test_obj),
                 "-", "-target", "x86_64-linux-gnu"],
                input=b"int dummy = 42;",
                capture_output=True,
            )
        result = subprocess.run(
            [str(zig_path), "ar", "cq", str(test_archive), str(test_obj)],
            capture_output=True, text=True,
        )
        return result.returncode == 0 and test_archive.exists()
    finally:
        for f in [test_obj, test_archive]:
            try:
                f.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            tmp_dir.rmdir()
        except OSError:
            pass


def _create_zig_ar_wrapper(zig_path: Path) -> Path:
    """Create an ar wrapper that works around zig's broken ar via MRI scripts."""
    wrapper_path = REPO_ROOT / ".zig_ar_wrapper.bat"
    zig_path_str = str(zig_path).replace("\\", "\\\\")
    content = f"""@echo off
setlocal enabledelayedexpansion
set "ZIG={zig_path_str}"
set "ARGS=%*"
"%ZIG%" ar %ARGS%
if %ERRORLEVEL% equ 0 exit /b 0
set "ARCHIVE="
set "FILES="
set "MODE=parse"
for %%a in (%ARGS%) do (
    if "!MODE!"=="parse" (
        set "arg=%%~a"
        if "!arg:~0,1!"=="-" (
            rem skip options
        ) else if "!arg!"=="cq" (
            set "MODE=archive"
        ) else if "!arg!"=="cr" (
            set "MODE=archive"
        ) else if "!arg!"=="rcs" (
            set "MODE=archive"
        ) else if "!arg!"=="q" (
            set "MODE=archive"
        ) else if "!arg!"=="r" (
            set "MODE=archive"
        ) else (
            set "MODE=files"
            set "ARCHIVE=%%~a"
        )
    ) else if "!MODE!"=="archive" (
        set "ARCHIVE=%%~a"
        set "MODE=files"
    ) else if "!MODE!"=="files" (
        if not defined FILES (
            set "FILES=%%~a"
        ) else (
            set "FILES=!FILES! %%~a"
        )
    )
)
if not defined ARCHIVE exit /b 1
set "MRI=%TEMP%\\ar_mri_%RANDOM%.txt"
echo create %ARCHIVE%>"%MRI%"
if defined FILES (
    for %%f in (!FILES!) do (
        echo addmod %%f>>"%MRI%"
    )
)
echo save>>"%MRI%"
echo end>>"%MRI%"
"%ZIG%" ar -M < "%MRI%"
set "EC=!ERRORLEVEL!"
del "%MRI%" 2>nul
exit /b !EC!
"""
    wrapper_path.write_text(content, encoding="ascii")
    print(f"Created zig ar wrapper: {wrapper_path}")
    return wrapper_path


def build_linux_cross_zigbuild(targets: list[str], msys2_path: str | None = None) -> None:
    """Cross-compile ZeroDPI for Linux using cargo-zigbuild.

    Builds the requested Linux targets from any host platform (Windows,
    macOS, etc.). Requires 'zig' and 'cargo-zigbuild' to be installed.
    On Windows, ``msys2_path`` is searched for the zig binary when it is
    not already on PATH.
    """
    label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
    print(f"=== Cross-compiling ZeroDPI for Linux ({label}) via cargo-zigbuild ===")

    zig_path = _find_zig_path(msys2_path)
    if zig_path is None:
        print(
            "Zig compiler not found.\n"
            "  Install it via MSYS2: pacman -S mingw-w64-clang-x86_64-zig\n"
            "  Or download from https://ziglang.org/download/"
        )
        die("Zig not found. Aborting.")

    print(f"Using zig: {zig_path}")

    # Verify zig works
    zv = subprocess.run(
        [str(zig_path), "version"],
        capture_output=True, text=True,
    )
    if zv.returncode != 0:
        die(f"zig at {zig_path} failed to run:\n{zv.stderr.strip()}")

    # Check if zig's ar works (broken in some dev versions)
    ar_works = _check_zig_ar_works(zig_path)
    if not ar_works:
        print("zig ar is broken (known issue in zig 0.17.0-dev) – creating MRI wrapper")
        ar_wrapper = _create_zig_ar_wrapper(zig_path)
    else:
        ar_wrapper = None

    # Verify cargo-zigbuild is installed (cargo is expected to be on PATH)
    zb = subprocess.run(
        ["cargo", "zigbuild", "--help"],
        capture_output=True, text=True,
    )
    if zb.returncode != 0:
        print(
            "cargo-zigbuild is not installed.\n"
            "  Install it with: cargo install --locked cargo-zigbuild"
        )
        die("cargo-zigbuild not found. Aborting.")

    ensure_rustup_targets(targets)

    extra_env: dict = {
        "CARGO_TERM_COLOR": "always",
        "PATH": f"{zig_path.parent};{os.environ.get('PATH', '')}",
    }

    if ar_wrapper is not None:
        for target in targets:
            name_dash = f"AR_{target.replace('-', '_')}"
            name_cargo = f"CARGO_TARGET_{target.upper().replace('-', '_')}_AR"
            extra_env[name_dash] = str(ar_wrapper)
            extra_env[name_cargo] = str(ar_wrapper)

    for target in targets:
        print(f"\n--- Building for {target} ---")
        run(
            ["cargo", "zigbuild", "--workspace", "--release", "--target", target],
            env=extra_env,
        )

        dist_dir = (REPO_ROOT / "dist" / "linux" / target) if len(targets) > 1 else (REPO_ROOT / "dist" / "linux")
        dist_dir.mkdir(parents=True, exist_ok=True)

        binary = REPO_ROOT / "target" / target / "release" / "zerodpi"
        if not binary.exists():
            die(f"Expected binary not found: {binary}")

        copy_required_file(binary, dist_dir / "zerodpi")
        copy_common_dist_files(dist_dir)
        copy_linux_dist_files(dist_dir)

        print_dist_contents(dist_dir)


# ---------------------------------------------------------------------------
# Windows build
# ---------------------------------------------------------------------------

def get_installed_windivert_version(dest_dir: Path) -> str | None:
    """Return the WinDivert version recorded in dest_dir, or None if absent."""
    version_file = dest_dir / WINDIVERT_VERSION_FILE
    if version_file.is_file():
        return version_file.read_text(encoding="utf-8").strip()
    return None


def missing_windivert_files(dest_dir: Path) -> list[str]:
    """Return the required WinDivert files that are absent from dest_dir."""
    return [name for name in WINDIVERT_REQUIRED_FILES if not (dest_dir / name).is_file()]


def download_windivert(dest_dir: Path, version: str) -> None:
    """Download and install WinDivert x64 runtime/link files into dest_dir."""
    url = WINDIVERT_RELEASE_URL.format(version=version)
    print(f"\nDownloading WinDivert {version} from:\n  {url}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        urllib.request.urlretrieve(url, tmp_path)
        with zipfile.ZipFile(tmp_path, "r") as zf:
            members = {Path(info.filename).as_posix(): info for info in zf.infolist()}
            for filename in WINDIVERT_REQUIRED_FILES:
                suffix = f"/x64/{filename}".lower()
                matches = [
                    info
                    for name, info in members.items()
                    if name.lower().endswith(suffix) and not info.is_dir()
                ]
                if not matches:
                    die(f"Downloaded WinDivert archive does not contain x64/{filename}.")
                with zf.open(matches[0]) as src, (dest_dir / filename).open("wb") as dst:
                    shutil.copyfileobj(src, dst)

        (dest_dir / WINDIVERT_VERSION_FILE).write_text(version + "\n", encoding="utf-8")
        print(f"WinDivert {version} installed to: {dest_dir}")
    except urllib.error.URLError as e:
        die(f"Failed to download WinDivert {version}: {e}")
    except zipfile.BadZipFile:
        die(f"Downloaded WinDivert archive is not a valid zip file: {tmp_path}")
    finally:
        tmp_path.unlink(missing_ok=True)


def ensure_windivert(dest_dir: Path, expected_version: str) -> None:
    """Download WinDivert when the repo-local copy is missing or stale."""
    missing = missing_windivert_files(dest_dir)
    installed = get_installed_windivert_version(dest_dir)
    if missing:
        print(
            "\nLocal WinDivert files are missing from "
            f"{dest_dir}:\n  " + "\n  ".join(missing)
        )
        download_windivert(dest_dir, expected_version)
        return

    if installed and installed != expected_version:
        print(
            f"\nLocal WinDivert version mismatch in {dest_dir} "
            f"(installed: {installed}, expected: {expected_version})."
        )
        download_windivert(dest_dir, expected_version)


def validate_local_windivert(dest_dir: Path, expected_version: str) -> None:
    """Verify the repo-local WinDivert files needed by windivert-sys exist."""
    missing = missing_windivert_files(dest_dir)
    if missing:
        die(
            "Local WinDivert files are missing from "
            f"{dest_dir}:\n  " + "\n  ".join(missing) +
            "\nAutomatic download failed. Place the WinDivert x64 release files in the repo's windivert/ folder."
        )

    installed = get_installed_windivert_version(dest_dir)
    if installed and installed != expected_version:
        die(
            f"Local WinDivert version mismatch in {dest_dir} "
            f"(installed: {installed}, expected: {expected_version}).\n"
            "Update windivert/ or pass --windivert-version to match the local files."
        )

    version = installed or "unknown version"
    print(f"\nUsing local WinDivert ({version}): {dest_dir}")


def build_windows(windivert_version: str, toolchain: str, msys2_path: str) -> None:
    print("=== Building ZeroDPI for Windows ===")

    windivert_dir = REPO_ROOT / "windivert"
    ensure_windivert(windivert_dir, windivert_version)
    validate_local_windivert(windivert_dir, windivert_version)

    # Build the cargo command, optionally prefixing with a toolchain specifier.
    cargo_cmd = ["cargo"]
    if toolchain:
        cargo_cmd.append(f"+{toolchain}")
    cargo_cmd += ["build", "--workspace", "--release"]

    # When using the GNU toolchain, prepend the MSYS2 mingw64 bin directory to
    # PATH so that rustc can locate dlltool, ld, and other GNU binutils by name.
    extra_env: dict = {
        "CARGO_TERM_COLOR": "always",
        "WINDIVERT_PATH": str(windivert_dir),
    }
    if msys2_path and toolchain and "gnu" in toolchain:
        mingw_bin = Path(msys2_path) / "mingw64" / "bin"
        msys_bin  = Path(msys2_path) / "usr" / "bin"
        extra_env["PATH"] = f"{mingw_bin};{msys_bin};{os.environ.get('PATH', '')}"

    run(cargo_cmd, env=extra_env)

    # Copy artifacts
    dist_dir = REPO_ROOT / "dist" / "windows"
    dist_dir.mkdir(parents=True, exist_ok=True)

    binary = CARGO_RELEASE_DIR / "zerodpi.exe"
    copy_required_file(binary, dist_dir / "zerodpi.exe")
    copy_common_dist_files(dist_dir)

    for dll_file in ("WinDivert.dll", "WinDivert64.sys"):
        src = windivert_dir / dll_file
        copy_required_file(src, dist_dir / dll_file)

    print_dist_contents(dist_dir)


# ---------------------------------------------------------------------------
# Termux build
# ---------------------------------------------------------------------------

def android_host_tag() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return "windows-x86_64"
    if system == "Linux":
        return "linux-x86_64"
    if system == "Darwin":
        return "darwin-arm64" if machine in ("arm64", "aarch64") else "darwin-x86_64"
    die(f"Unsupported Android NDK host platform: {system}")


def _find_android_studio_ndk() -> Path | None:
    """Search common Android Studio NDK installation paths."""
    candidates = []

    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        sdk_ndk = Path(local_appdata) / "Android" / "Sdk" / "ndk"
        if sdk_ndk.is_dir():
            candidates.extend(sorted(sdk_ndk.iterdir()))

    for base in (
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Android" / "Android Studio" / "ndk",
        Path(os.environ.get("ProgramW6432", "C:\\Program Files")) / "Android" / "Android Studio" / "ndk",
    ):
        if base.is_dir():
            candidates.extend(sorted(base.iterdir()))

    for candidate in candidates:
        ndk_dir = candidate if candidate.is_dir() else None
        if ndk_dir and (ndk_dir / "toolchains" / "llvm").is_dir():
            return ndk_dir
    return None


def resolve_android_ndk(android_ndk: str | None) -> Path:
    ndk = android_ndk or os.environ.get("ANDROID_NDK_HOME")
    if ndk:
        ndk_path = Path(ndk).expanduser().resolve()
        if ndk_path.is_dir():
            return ndk_path

    auto = _find_android_studio_ndk()
    if auto is not None:
        print(f"Android NDK auto-detected at: {auto}")
        return auto

    print("Android NDK not found (set ANDROID_NDK_HOME or pass --android-ndk).")
    confirm_or_die(f"Download Android NDK {ANDROID_NDK_DEFAULT_VERSION} now?")
    return download_android_ndk(ANDROID_NDK_DEFAULT_VERSION)


def cargo_target_env_name(rust_target: str, suffix: str) -> str:
    normalized = rust_target.upper().replace("-", "_")
    return f"CARGO_TARGET_{normalized}_{suffix}"


def android_tool_path(ndk_path: Path, tool_name: str) -> Path:
    if platform.system() == "Windows":
        tool_name += ".cmd"
    return ndk_path / "toolchains" / "llvm" / "prebuilt" / android_host_tag() / "bin" / tool_name


def android_clang_path(ndk_path: Path, arch: str, api_level: int, cxx: bool = False) -> Path:
    clang_name = f"{TERMUX_CLANG_TARGETS[arch]}{api_level}-clang"
    if cxx:
        clang_name += "++"
    return android_tool_path(ndk_path, clang_name)


def add_target_tool_env(env: dict, name: str, rust_target: str, tool_path: Path) -> None:
    env[f"{name}_{rust_target}"] = str(tool_path)
    env[f"{name}_{rust_target.replace('-', '_')}"] = str(tool_path)


def android_ar_path(ndk_path: Path) -> Path:
    ar_name = "llvm-ar"
    if platform.system() == "Windows":
        ar_name += ".exe"
    return ndk_path / "toolchains" / "llvm" / "prebuilt" / android_host_tag() / "bin" / ar_name


def resolve_termux_arches(arch_arg: str) -> list[str]:
    if arch_arg == "all":
        return list(TERMUX_ARM_ARCHES)
    if arch_arg in TERMUX_RUST_TARGETS:
        return [arch_arg]

    supported = ", ".join(TERMUX_ARCH_CHOICES)
    die(f"Unsupported Termux architecture: {arch_arg}. Supported values: {supported}")


def build_termux_arch(arch: str, ndk_path: Path, android_api: int) -> None:
    if arch not in TERMUX_RUST_TARGETS:
        supported = ", ".join(sorted(TERMUX_RUST_TARGETS))
        die(f"Unsupported Termux architecture: {arch}. Supported values: {supported}")

    print(f"\n--- Building Termux Android package ({arch}) ---")
    rust_target = TERMUX_RUST_TARGETS[arch]
    linker = android_clang_path(ndk_path, arch, android_api)
    cxx = android_clang_path(ndk_path, arch, android_api, cxx=True)
    ar = android_ar_path(ndk_path)
    if not linker.is_file():
        die(
            "Expected Android NDK clang linker not found: "
            f"{linker}\nCheck --android-ndk, --termux-arch, and --android-api."
        )
    if not cxx.is_file():
        die(f"Expected Android NDK clang++ compiler not found: {cxx}")
    if not ar.is_file():
        die(f"Expected Android NDK llvm-ar not found: {ar}")

    env = {
        "CARGO_TERM_COLOR": "always",
        cargo_target_env_name(rust_target, "LINKER"): str(linker),
    }
    add_target_tool_env(env, "CC", rust_target, linker)
    add_target_tool_env(env, "CXX", rust_target, cxx)
    add_target_tool_env(env, "AR", rust_target, ar)
    run(
        ["cargo", "build", "--workspace", "--release", "--target", rust_target],
        env=env,
    )

    dist_dir = REPO_ROOT / "dist" / "termux" / arch
    dist_dir.mkdir(parents=True, exist_ok=True)

    binary = REPO_ROOT / "target" / rust_target / "release" / "zerodpi"
    copy_required_file(binary, dist_dir / "zerodpi")
    copy_common_dist_files(dist_dir)

    print_dist_contents(dist_dir)


def build_termux(arch_arg: str, android_ndk: str | None, android_api: int) -> None:
    arches = resolve_termux_arches(arch_arg)
    label = ", ".join(arches)
    print(f"=== Building ZeroDPI for Termux ({label}) ===")

    if android_api < ANDROID_DEFAULT_API_LEVEL:
        die(f"Android API level must be {ANDROID_DEFAULT_API_LEVEL} or newer.")

    rust_targets = sorted({TERMUX_RUST_TARGETS[arch] for arch in arches})
    ensure_rustup_targets(rust_targets)

    ndk_path = resolve_android_ndk(android_ndk)
    for arch in arches:
        build_termux_arch(arch, ndk_path, android_api)


# ---------------------------------------------------------------------------
# All platforms
# ---------------------------------------------------------------------------

def build_all(
    windivert_version: str,
    toolchain: str,
    msys2_path: str,
    termux_arch: str,
    android_ndk: str | None,
    android_api: int,
    linux_targets: list[str] | None = None,
) -> None:
    """Build for Windows, Linux (cross-compiled), and Termux (Android)."""
    if linux_targets is None:
        linux_targets = [DEFAULT_LINUX_TARGET]
    print("=" * 60)
    print("  ZeroDPI – Building for ALL platforms")
    print("=" * 60)

    exit_code = 0

    # 1. Windows
    print("\n\n")
    try:
        build_windows(windivert_version, toolchain, msys2_path)
    except SystemExit as e:
        print(f"\n[SKIP] Windows build skipped: {e}")
        exit_code = exit_code or 1

    # 2. Linux (cross-compile via cargo-zigbuild)
    print("\n\n")
    try:
        build_linux_cross_zigbuild(linux_targets, msys2_path)
    except SystemExit as e:
        print(f"\n[SKIP] Linux build skipped: {e}")
        exit_code = exit_code or 1

    # 3. Termux / Android
    print("\n\n")
    try:
        build_termux(termux_arch, android_ndk, android_api)
    except SystemExit as e:
        print(f"\n[SKIP] Termux build skipped: {e}")
        exit_code = exit_code or 1

    print("\n" + "=" * 60)
    print("  Platform builds complete!")
    print("=" * 60)
    termux_paths = [f"termux/{arch}" for arch in resolve_termux_arches(termux_arch)]
    for p in ("windows", "linux", *termux_paths):
        d = REPO_ROOT / "dist" / Path(*p.split("/"))
        if d.is_dir():
            print(f"  {d}")
        else:
            print(f"  {REPO_ROOT / 'dist' / p} (not built)")

    if exit_code:
        sys.exit(exit_code)

    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build ZeroDPI for the current platform, Windows, Linux, or Termux.")
    parser.add_argument(
        "--platform",
        "--target",
        dest="platform",
        choices=("auto", "linux", "windows", "termux", "all"),
        default="auto",
        help="Build platform (default: auto-detect host OS). Use 'all' to build for Windows, Linux, and Termux.",
    )
    parser.add_argument(
        "--windivert-version",
        default=WINDIVERT_DEFAULT_VERSION,
        metavar="VER",
        help=f"WinDivert release to download/verify (Windows only, default: {WINDIVERT_DEFAULT_VERSION})",
    )
    parser.add_argument(
        "--toolchain",
        default=WINDOWS_DEFAULT_TOOLCHAIN,
        metavar="TOOLCHAIN",
        help=(
            f"Rust toolchain to use for the cargo build (Windows only, "
            f"default: {WINDOWS_DEFAULT_TOOLCHAIN}). "
            "Pass an empty string to use the workspace default toolchain."
        ),
    )
    parser.add_argument(
        "--msys2-path",
        default=WINDOWS_DEFAULT_MSYS2_PATH,
        metavar="PATH",
        help=(
            f"Path to the MSYS2 installation (Windows + GNU toolchain only, "
            f"default: {WINDOWS_DEFAULT_MSYS2_PATH}). "
            "Its mingw64/bin is prepended to PATH so that dlltool and ld are "
            "reachable by the Rust GNU toolchain."
        ),
    )
    parser.add_argument(
        "--termux-arch",
        choices=TERMUX_ARCH_CHOICES,
        default=TERMUX_DEFAULT_ARCH,
        help=(
            f"Termux Android architecture (default: {TERMUX_DEFAULT_ARCH}, "
            f"builds {', '.join(TERMUX_ARM_ARCHES)})."
        ),
    )
    parser.add_argument(
        "--android-ndk",
        metavar="PATH",
        help="Android NDK path for Termux builds. Defaults to ANDROID_NDK_HOME.",
    )
    parser.add_argument(
        "--android-api",
        type=int,
        default=ANDROID_DEFAULT_API_LEVEL,
        metavar="LEVEL",
        help=f"Android API level for the NDK clang linker (Termux only, default: {ANDROID_DEFAULT_API_LEVEL}).",
    )
    parser.add_argument(
        "--linux-target",
        default=DEFAULT_LINUX_TARGET,
        metavar="TARGET",
        help=(
            f"Linux cross-compilation target (default: {DEFAULT_LINUX_TARGET}). "
            "Use 'all' to build for all supported targets: "
            f"{', '.join(LINUX_CROSS_TARGETS)}. "
            "Short aliases like 'x86_64', 'aarch64', 'x86_64-musl', "
            "'aarch64-musl' are also accepted."
        ),
    )
    args = parser.parse_args()

    selected_platform = args.platform
    if selected_platform == "auto":
        system = platform.system()
        if system == "Linux":
            selected_platform = "linux"
        elif system == "Windows":
            selected_platform = "windows"
        else:
            die(f"Unsupported platform: {system}. Only Linux and Windows are auto-detected. Use --platform all to build everything from any host.")

    if selected_platform == "linux":
        if platform.system() == "Windows":
            targets = resolve_linux_targets(args.linux_target)
            build_linux_cross_zigbuild(targets, args.msys2_path)
        else:
            build_linux()
    elif selected_platform == "windows":
        build_windows(args.windivert_version, args.toolchain, args.msys2_path)
    elif selected_platform == "termux":
        build_termux(args.termux_arch, args.android_ndk, args.android_api)
    elif selected_platform == "all":
        build_all(
            args.windivert_version,
            args.toolchain,
            args.msys2_path,
            args.termux_arch,
            args.android_ndk,
            args.android_api,
            resolve_linux_targets(args.linux_target),
        )
    else:
        die(f"Unsupported platform: {selected_platform}")


if __name__ == "__main__":
    main()
