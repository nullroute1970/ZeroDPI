#!/usr/bin/env python3
"""
build.py - Build ZeroDPI for the current platform, Windows, Linux, Termux, or Android.

Usage:
    python build.py [--platform linux|windows|termux|android|android-app|all]
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
     stable-x86_64-pc-windows-msvc). Pass --toolchain="" to use the workspace
     default toolchain instead.
  3. Copies zerodpi.exe + WinDivert.dll + WinDivert64.sys + config.toml +
     sni_list.txt + ip_list.txt + README.md to dist/windows/.

Termux:
  1. Finds the Android NDK from --android-ndk or ANDROID_NDK_HOME.
  2. Configures Cargo to use the selected NDK clang linker.
  3. Runs `cargo build --workspace --release --target <android-target>`.
  4. Copies zerodpi + config.toml + sni_list.txt + ip_list.txt + README.md
     to dist/termux/<arch>/. The default `all` builds Android ARMv7 and ARMv8.

Android app runtime:
  1. Reuses the Android NDK target setup from Termux builds.
  2. Builds ABI-specific zerodpi executables for APK packaging.
  3. Stages jniLibs/<abi>/libzerodpi_exec.so plus bin/<abi>/zerodpi under
     dist/android-app/<rootless|full>/.
  4. Runs the Android Gradle project and copies the APK into the same dist dir.
  5. The default rootless runtime disables NFQUEUE packet interception so the
     first APK runtime can ship without external netfilter dependencies.
"""

import argparse
import json
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
# On Windows this project targets the MSVC toolchain by default.
WINDOWS_DEFAULT_TOOLCHAIN = "stable-x86_64-pc-windows-msvc"
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
ANDROID_APP_PUBLIC_ABIS = ("arm64-v8a", "armeabi-v7a")
ANDROID_APP_DEBUG_ABIS = ANDROID_APP_PUBLIC_ABIS + ("x86_64",)
ANDROID_APP_ABI_TARGETS = {
    "armeabi-v7a": ("armv7", "armv7-linux-androideabi"),
    "arm64-v8a": ("armv8", "aarch64-linux-android"),
    "x86_64": ("x86_64", "x86_64-linux-android"),
}
ANDROID_APP_ABI_ALIASES = {
    "armv7": "armeabi-v7a",
    "arm": "armeabi-v7a",
    "armeabi-v7a": "armeabi-v7a",
    "armv8": "arm64-v8a",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "arm64-v8a": "arm64-v8a",
    "x86_64": "x86_64",
}
ANDROID_APP_ABI_CHOICES = ("all", "public", "debug") + tuple(sorted(ANDROID_APP_ABI_ALIASES))
ANDROID_APP_RUNTIME_CHOICES = ("rootless", "full", "both")
ANDROID_APP_BUILD_TYPES = ("debug", "release")
ANDROID_GRADLE_FALLBACK_VERSION = "9.5.0"
ANDROID_GRADLE_INCOMPATIBLE_MIN_VERSION = (9, 6)
ANDROID_GRADLE_BUILD_ARGS = (
    "-Pkotlin.compiler.execution.strategy=in-process",
    "--no-daemon",
    "--rerun-tasks",
)
REPO_ROOT = Path(__file__).resolve().parent
ANDROID_PROJECT_DIR = REPO_ROOT / "android"
ANDROID_APP_MODULE_DIR = ANDROID_PROJECT_DIR / "app"
ANDROID_GRADLE_DIST_DIR = REPO_ROOT / ".gradle-dist"
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

def _detect_pkg_manager() -> str:
    """Return 'apt', 'pacman', or 'dnf' based on the current distro."""
    if shutil.which("dpkg") and shutil.which("apt-get"):
        return "apt"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("dnf"):
        return "dnf"
    return "unknown"


def check_nfqueue_dev() -> bool:
    """Return True if libnetfilter-queue headers are present."""
    pm = _detect_pkg_manager()
    if pm == "apt":
        result = subprocess.run(
            ["dpkg", "-s", "libnetfilter-queue-dev"],
            capture_output=True,
        )
        return result.returncode == 0
    if pm == "pacman":
        result = subprocess.run(
            ["pacman", "-Q", "libnetfilter_queue"],
            capture_output=True,
        )
        return result.returncode == 0
    if pm == "dnf":
        result = subprocess.run(
            ["rpm", "-q", "libnetfilter_queue-devel"],
            capture_output=True,
        )
        return result.returncode == 0
    return False


def build_linux() -> None:
    print("=== Building ZeroDPI for Linux ===")

    # Check libnetfilter-queue-dev
    if not check_nfqueue_dev():
        pm = _detect_pkg_manager()
        if pm == "apt":
            pkg = "libnetfilter-queue-dev"
            answer = input(f"{pkg} is not installed. Install with apt-get? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes"):
                run(["sudo", "apt-get", "update"])
                run(["sudo", "apt-get", "install", "-y", pkg])
            else:
                die(f"{pkg} is required. Aborting.")
        elif pm == "pacman":
            pkg = "libnetfilter_queue"
            answer = input(f"{pkg} is not installed. Install with pacman? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes"):
                run(["sudo", "pacman", "-S", "--noconfirm", pkg])
            else:
                die(f"{pkg} is required. Aborting.")
        elif pm == "dnf":
            pkg = "libnetfilter_queue-devel"
            answer = input(f"{pkg} is not installed. Install with dnf? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes"):
                run(["sudo", "dnf", "install", "-y", pkg])
            else:
                die(f"{pkg} is required. Aborting.")
        else:
            die("Cannot detect package manager. Install libnetfilter-queue development headers manually.")

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
    """Search common NDK installation paths, prioritizing SDK subdirectories."""
    # 1. Check environment variables
    for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"):
        val = os.environ.get(name)
        if val:
            p = Path(val).expanduser().resolve()
            if p.is_dir() and (p / "toolchains" / "llvm").is_dir():
                return p

    # Helper function to check an NDK dir or search within a parent 'ndk' dir
    def check_ndk_dir(path: Path) -> Path | None:
        if not path.is_dir():
            return None
        # If this is the 'ndk' parent directory containing version folders
        if path.name == "ndk":
            try:
                # Find all version directories, sort descending to check newest version first
                versions = sorted(
                    [sub for sub in path.iterdir() if sub.is_dir()],
                    key=lambda x: x.name,
                    reverse=True,
                )
                for v in versions:
                    if (v / "toolchains" / "llvm").is_dir():
                        return v
            except OSError:
                pass
        # If this is a specific NDK bundle or directory
        elif (path / "toolchains" / "llvm").is_dir():
            return path
        return None

    # 2. Find the SDK first, then check inside it
    sdk = resolve_android_sdk(None)
    if sdk:
        for suffix in ("ndk", "ndk-bundle"):
            res = check_ndk_dir(sdk / suffix)
            if res:
                return res

    # 3. Check standard locations by OS
    home = Path.home()
    candidates = []
    if platform.system() == "Windows":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Android" / "Sdk" / "ndk")
            candidates.append(Path(local_appdata) / "Android" / "Sdk" / "ndk-bundle")
        candidates.append(home / "AppData" / "Local" / "Android" / "Sdk" / "ndk")
        candidates.append(home / "AppData" / "Local" / "Android" / "Sdk" / "ndk-bundle")
        for env_name in ("ProgramFiles", "ProgramW6432"):
            pf = os.environ.get(env_name)
            if pf:
                candidates.append(Path(pf) / "Android" / "Android Studio" / "ndk")
                candidates.append(Path(pf) / "Android" / "Android Studio" / "ndk-bundle")
    elif platform.system() == "Darwin":
        candidates.append(home / "Library" / "Android" / "sdk" / "ndk")
        candidates.append(home / "Library" / "Android" / "sdk" / "ndk-bundle")
        candidates.append(Path("/Library/Android/sdk/ndk"))
        candidates.append(Path("/Library/Android/sdk/ndk-bundle"))
    else:
        candidates.extend([
            home / "Android" / "Sdk" / "ndk",
            home / "Android" / "Sdk" / "ndk-bundle",
            home / "Android" / "sdk" / "ndk",
            home / "Android" / "sdk" / "ndk-bundle",
            Path("/opt/android-sdk/ndk"),
            Path("/opt/android-sdk/ndk-bundle"),
            Path("/usr/lib/android-sdk/ndk"),
            Path("/usr/lib/android-sdk/ndk-bundle"),
        ])

    for c in candidates:
        res = check_ndk_dir(c)
        if res:
            return res

    # 4. Check all environment variables containing 'ndk'
    for key, value in os.environ.items():
        if "ndk" in key.lower() and os.path.isdir(value):
            p = Path(value).resolve()
            if (p / "toolchains" / "llvm").is_dir():
                return p

    return None


def resolve_android_ndk(android_ndk: str | None) -> Path:
    if android_ndk:
        ndk_path = Path(android_ndk).expanduser().resolve()
        if ndk_path.is_dir() and (ndk_path / "toolchains" / "llvm").is_dir():
            return ndk_path

    # First check default env vars specifically
    for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"):
        val = os.environ.get(name)
        if val:
            p = Path(val).expanduser().resolve()
            if p.is_dir() and (p / "toolchains" / "llvm").is_dir():
                return p

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
# Android app runtime artifacts
# ---------------------------------------------------------------------------

def resolve_android_app_abis(abi_arg: str) -> list[str]:
    """Resolve the Android app ABI argument to APK ABI directory names."""
    if abi_arg in ("all", "public"):
        return list(ANDROID_APP_PUBLIC_ABIS)
    if abi_arg == "debug":
        return list(ANDROID_APP_DEBUG_ABIS)

    abis: list[str] = []
    for raw in abi_arg.split(","):
        item = raw.strip()
        if not item:
            continue
        abi = ANDROID_APP_ABI_ALIASES.get(item)
        if abi is None:
            supported = ", ".join(ANDROID_APP_ABI_CHOICES)
            die(f"Unsupported Android app ABI: {item}. Supported values: {supported}")
        if abi not in abis:
            abis.append(abi)

    if not abis:
        die("At least one Android app ABI must be selected.")
    return abis


def resolve_android_app_runtimes(runtime_arg: str) -> list[str]:
    if runtime_arg == "both":
        return ["rootless", "full"]
    if runtime_arg in ANDROID_APP_RUNTIME_CHOICES:
        return [runtime_arg]
    supported = ", ".join(ANDROID_APP_RUNTIME_CHOICES)
    die(f"Unsupported Android app runtime variant: {runtime_arg}. Supported values: {supported}")


def android_build_env(
    arch: str,
    rust_target: str,
    ndk_path: Path,
    android_api: int,
) -> dict:
    linker = android_clang_path(ndk_path, arch, android_api)
    cxx = android_clang_path(ndk_path, arch, android_api, cxx=True)
    ar = android_ar_path(ndk_path)
    if not linker.is_file():
        die(
            "Expected Android NDK clang linker not found: "
            f"{linker}\nCheck --android-ndk, Android ABI, and --android-api."
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
    return env


def copy_android_app_runtime_templates(dist_dir: Path) -> None:
    assets_dir = dist_dir / "assets" / "zerodpi"
    assets_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("config.toml", "sni_list.txt", "ip_list.txt"):
        copy_required_file(REPO_ROOT / filename, assets_dir / filename)


def reset_android_app_runtime_inputs(dist_dir: Path) -> None:
    for dirname in ("assets", "bin", "jniLibs"):
        shutil.rmtree(dist_dir / dirname, ignore_errors=True)
    for apk in dist_dir.glob("zerodpi-android-*.apk"):
        apk.unlink()
    manifest = dist_dir / "zerodpi-runtime-manifest.json"
    if manifest.exists():
        manifest.unlink()


def write_android_app_manifest(
    dist_dir: Path,
    runtime: str,
    android_api: int,
    entries: list[dict],
) -> None:
    manifest = {
        "artifact": "zerodpi-android-app-runtime",
        "runtime": runtime,
        "androidApi": android_api,
        "packetInterception": runtime == "full",
        "nativeLibraryExecutable": "libzerodpi_exec.so",
        "command": "zerodpi --config <app-private>/config.toml --no-tui --auto-select --json-events",
        "packaging": {
            "jniLibs": "Copy jniLibs/ into the Android app module so PackageManager extracts the ABI-matched native artifact into nativeLibraryDir.",
            "standaloneBin": "bin/<abi>/zerodpi is for adb/device smoke tests and is not the normal APK execution path.",
            "policy": "Do not rely on executing a binary copied into writable app data. The process-wrapper MVP should execute the extracted native artifact from nativeLibraryDir unless device testing proves another location is allowed.",
        },
        "abis": entries,
    }
    (dist_dir / "zerodpi-runtime-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def print_android_app_contents(dist_dir: Path) -> None:
    print(f"\n=== Android app runtime artifacts in: {dist_dir} ===")
    for f in sorted(dist_dir.rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(dist_dir)}")


def parse_gradle_version(output: str) -> tuple[int, ...] | None:
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("Gradle "):
            continue
        raw_version = line.split(None, 1)[1]
        parts: list[int] = []
        for part in raw_version.split("."):
            digits = ""
            for ch in part:
                if not ch.isdigit():
                    break
                digits += ch
            if not digits:
                break
            parts.append(int(digits))
        if parts:
            return tuple(parts)
    return None


def version_at_least(version: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    width = max(len(version), len(minimum))
    padded_version = version + (0,) * (width - len(version))
    padded_minimum = minimum + (0,) * (width - len(minimum))
    return padded_version >= padded_minimum


def format_gradle_version(version: tuple[int, ...] | None) -> str:
    if version is None:
        return "unknown"
    return ".".join(str(part) for part in version)


def gradle_command_version(cmd: list[str]) -> tuple[int, ...] | None:
    result = subprocess.run(
        [*cmd, "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return parse_gradle_version(f"{result.stdout}\n{result.stderr}")


def is_android_gradle_incompatible(version: tuple[int, ...] | None) -> bool:
    return version is not None and version_at_least(
        version,
        ANDROID_GRADLE_INCOMPATIBLE_MIN_VERSION,
    )


def android_gradle_executable(dist_dir: Path) -> Path:
    script = "gradle.bat" if platform.system() == "Windows" else "gradle"
    return dist_dir / "bin" / script


def ensure_android_gradle_distribution(version: str = ANDROID_GRADLE_FALLBACK_VERSION) -> Path:
    dist_dir = ANDROID_GRADLE_DIST_DIR / f"gradle-{version}"
    gradle = android_gradle_executable(dist_dir)
    if gradle.is_file():
        return gradle

    url = f"https://services.gradle.org/distributions/gradle-{version}-bin.zip"
    print(
        "\nDownloading compatible Gradle distribution "
        f"{version} for Android APK builds:\n  {url}"
    )
    ANDROID_GRADLE_DIST_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        urllib.request.urlretrieve(url, tmp_path)
        with zipfile.ZipFile(tmp_path, "r") as zf:
            zf.extractall(ANDROID_GRADLE_DIST_DIR)
    finally:
        tmp_path.unlink(missing_ok=True)

    if not gradle.is_file():
        die(f"Downloaded Gradle {version}, but expected executable was not found: {gradle}")
    if platform.system() != "Windows":
        gradle.chmod(gradle.stat().st_mode | 0o111)
    return gradle


def resolve_explicit_gradle_command(android_gradle: str) -> list[str]:
    gradle_path = Path(android_gradle).expanduser()
    if gradle_path.is_file():
        return [str(gradle_path.resolve())]
    gradle_on_path = shutil.which(android_gradle)
    if gradle_on_path:
        return [gradle_on_path]
    die(f"Gradle executable not found: {android_gradle}")


def unescape_android_property_value(value: str) -> str:
    return (
        value.strip()
        .replace(r"\ ", " ")
        .replace(r"\:", ":")
        .replace(r"\\", "\\")
    )


def read_android_local_properties_sdk() -> Path | None:
    local_properties = ANDROID_PROJECT_DIR / "local.properties"
    if not local_properties.is_file():
        return None

    for line in local_properties.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        if stripped.startswith("sdk.dir"):
            _, _, raw_value = stripped.partition("=")
            if not raw_value:
                _, _, raw_value = stripped.partition(":")
            if raw_value:
                sdk_path = Path(unescape_android_property_value(raw_value)).expanduser()
                if not sdk_path.is_absolute():
                    sdk_path = ANDROID_PROJECT_DIR / sdk_path
                return sdk_path

    return None


def android_sdk_candidates(ndk_path: Path | None) -> list[Path]:
    candidates: list[Path] = []

    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        sdk = os.environ.get(name)
        if sdk:
            candidates.append(Path(sdk).expanduser())

    local_properties_sdk = read_android_local_properties_sdk()
    if local_properties_sdk is not None:
        candidates.append(local_properties_sdk)

    if ndk_path:
        # If NDK path is like <SDK>/ndk/<version> or <SDK>/ndk-bundle
        if ndk_path.parent.name == "ndk":
            candidates.append(ndk_path.parent.parent)
        elif ndk_path.name == "ndk-bundle":
            candidates.append(ndk_path.parent)
        else:
            candidates.append(ndk_path.parent)

    # Common location detection using Path.home() which is cross-platform
    home = Path.home()
    if platform.system() == "Windows":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Android" / "Sdk")
        candidates.append(home / "AppData" / "Local" / "Android" / "Sdk")
        candidates.append(home / "Android" / "Sdk")
        candidates.append(Path("C:\\Android\\sdk"))
        candidates.append(Path("C:\\Android\\Sdk"))
    elif platform.system() == "Darwin":
        candidates.append(home / "Library" / "Android" / "sdk")
        candidates.append(Path("/Library/Android/sdk"))
    else:
        candidates.extend(
            [
                home / "Android" / "Sdk",
                home / "Android" / "sdk",
                home / "android-sdk",
                Path("/opt/android-sdk"),
                Path("/var/lib/android-sdk"),
                Path("/usr/lib/android-sdk"),
            ]
        )

    # Let's also check if standard environment variables contain SDK paths
    for key, value in os.environ.items():
        if "sdk" in key.lower() or "android" in key.lower():
            if os.path.isdir(value):
                candidates.append(Path(value))

    # Deduplicate candidates while maintaining order
    seen = set()
    deduped = []
    for c in candidates:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    return deduped


def resolve_android_sdk(ndk_path: Path | None) -> Path | None:
    # First pass: look for a fully valid SDK directory
    for sdk_path in android_sdk_candidates(ndk_path):
        if sdk_path.is_dir():
            # Check structure
            if (sdk_path / "platforms").is_dir() or (sdk_path / "platform-tools").is_dir() or (sdk_path / "build-tools").is_dir():
                return sdk_path

    # Second pass: fall back to any existing directory candidate
    for sdk_path in android_sdk_candidates(ndk_path):
        if sdk_path.is_dir():
            return sdk_path

    return None


def java_executable(java_home: Path) -> Path:
    script = "java.exe" if platform.system() == "Windows" else "java"
    return java_home / "bin" / script


def java_home_major_version(java_home: Path) -> int | None:
    java = java_executable(java_home)
    if not java.is_file():
        return None

    result = subprocess.run(
        [str(java), "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = f"{result.stdout}\n{result.stderr}"
    marker = 'version "'
    start = output.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = output.find('"', start)
    if end == -1:
        return None

    raw_version = output[start:end]
    if raw_version.startswith("1."):
        raw_version = raw_version[2:]
    major = raw_version.split(".", 1)[0]
    return int(major) if major.isdigit() else None


def android_java_home_candidates() -> list[Path]:
    candidates: list[Path] = []

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home).expanduser())

    if platform.system() == "Windows":
        for env_name in ("ProgramFiles", "ProgramW6432"):
            program_files = os.environ.get(env_name)
            if not program_files:
                continue
            candidates.append(Path(program_files) / "Android" / "Android Studio" / "jbr")
            java_dir = Path(program_files) / "Java"
            if java_dir.is_dir():
                candidates.extend(sorted(java_dir.glob("jdk-21*"), reverse=True))
                candidates.extend(sorted(java_dir.glob("jdk-17*"), reverse=True))
    elif platform.system() == "Darwin":
        candidates.append(Path("/Applications/Android Studio.app/Contents/jbr/Contents/Home"))
        java_vm_dir = Path("/Library/Java/JavaVirtualMachines")
        if java_vm_dir.is_dir():
            candidates.extend(sorted(java_vm_dir.glob("jdk-21*.jdk/Contents/Home"), reverse=True))
            candidates.extend(sorted(java_vm_dir.glob("jdk-17*.jdk/Contents/Home"), reverse=True))
    else:
        jvm_dir = Path("/usr/lib/jvm")
        if jvm_dir.is_dir():
            candidates.extend(sorted(jvm_dir.glob("java-21*"), reverse=True))
            candidates.extend(sorted(jvm_dir.glob("jdk-21*"), reverse=True))
            candidates.extend(sorted(jvm_dir.glob("java-17*"), reverse=True))
            candidates.extend(sorted(jvm_dir.glob("jdk-17*"), reverse=True))

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(resolved)
    return deduped


def resolve_android_java_home() -> Path | None:
    fallback: Path | None = None
    for candidate in android_java_home_candidates():
        major = java_home_major_version(candidate)
        if major is None:
            continue
        if fallback is None:
            fallback = candidate
        if 17 <= major <= 21:
            return candidate
    return fallback


def android_gradle_env(ndk_path: Path | None) -> dict:
    env: dict = {}
    sdk_path = resolve_android_sdk(ndk_path)
    if sdk_path is None:
        local_properties = ANDROID_PROJECT_DIR / "local.properties"
        if not local_properties.is_file():
            die(
                "Android SDK not found. Set ANDROID_HOME or ANDROID_SDK_ROOT, "
                f"or create {local_properties} with sdk.dir=<path>."
            )
    else:
        print(f"Android SDK detected at: {sdk_path}")
        env.update(
            {
                "ANDROID_HOME": str(sdk_path),
                "ANDROID_SDK_ROOT": str(sdk_path),
            }
        )

    java_home = resolve_android_java_home()
    if java_home is not None:
        print(f"Android Gradle JAVA_HOME: {java_home}")
        env["JAVA_HOME"] = str(java_home)
        env["PATH"] = f"{java_home / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"

    return env


def resolve_gradle_command(android_gradle: str | None) -> list[str]:
    if not ANDROID_PROJECT_DIR.is_dir():
        die(f"Android project directory not found: {ANDROID_PROJECT_DIR}")

    if android_gradle:
        cmd = resolve_explicit_gradle_command(android_gradle)
        version = gradle_command_version(cmd)
        if is_android_gradle_incompatible(version):
            die(
                f"Gradle {format_gradle_version(version)} is incompatible with "
                "this Android Gradle Plugin 8.x project. Use Gradle "
                f"{ANDROID_GRADLE_FALLBACK_VERSION}, or omit --android-gradle "
                "to let build.py use a compatible local distribution."
            )
        return cmd

    wrapper = ANDROID_PROJECT_DIR / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    if wrapper.is_file():
        cmd = [str(wrapper)]
        version = gradle_command_version(cmd)
        if not is_android_gradle_incompatible(version):
            return cmd
        print(
            f"Android Gradle wrapper version {format_gradle_version(version)} is "
            "incompatible with this AGP 8.x project; using a compatible local "
            f"Gradle {ANDROID_GRADLE_FALLBACK_VERSION} distribution."
        )

    gradle_on_path = shutil.which("gradle")
    if gradle_on_path:
        cmd = [gradle_on_path]
        version = gradle_command_version(cmd)
        if not is_android_gradle_incompatible(version):
            return cmd
        print(
            f"Gradle {format_gradle_version(version)} on PATH is incompatible "
            "with this AGP 8.x project; using a compatible local "
            f"Gradle {ANDROID_GRADLE_FALLBACK_VERSION} distribution."
        )

    return [str(ensure_android_gradle_distribution())]


def android_gradle_task(build_type: str) -> str:
    return f":app:assemble{build_type.capitalize()}"


def is_unsigned_android_apk(apk: Path) -> bool:
    return apk.name.endswith("-unsigned.apk")


def android_packaged_apk_name(runtime: str, build_type: str, apk: Path) -> str:
    suffix = (
        "-unsigned"
        if build_type == "release" and is_unsigned_android_apk(apk)
        else ""
    )
    return f"zerodpi-android-{runtime}-{build_type}{suffix}.apk"


def find_android_apk(build_type: str) -> Path:
    output_dir = ANDROID_APP_MODULE_DIR / "build" / "outputs" / "apk" / build_type
    apks = sorted(
        output_dir.glob(f"app-{build_type}*.apk"),
        key=lambda apk: apk.stat().st_mtime,
        reverse=True,
    )
    if not apks:
        apks = sorted(
            output_dir.glob("*.apk"),
            key=lambda apk: apk.stat().st_mtime,
            reverse=True,
        )
    if not apks:
        die(f"Expected Android APK not found under: {output_dir}")
    return apks[0]


def build_android_app_apk(
    runtime: str,
    dist_dir: Path,
    build_type: str,
    android_gradle: str | None,
    ndk_path: Path | None,
) -> Path:
    print(f"\n--- Building Android APK ({runtime}, {build_type}) ---")
    gradle_cmd = resolve_gradle_command(android_gradle)
    run(
        [
            *gradle_cmd,
            "-p",
            str(ANDROID_PROJECT_DIR),
            f"-PzerodpiRuntimeDir={dist_dir}",
            android_gradle_task(build_type),
            *ANDROID_GRADLE_BUILD_ARGS,
        ],
        env=android_gradle_env(ndk_path),
    )

    apk = find_android_apk(build_type)
    packaged_apk = dist_dir / android_packaged_apk_name(runtime, build_type, apk)
    copy_required_file(apk, packaged_apk)
    if build_type == "release" and is_unsigned_android_apk(apk):
        print(
            "WARNING: Gradle produced an unsigned release APK. It was copied for "
            "manual signing; configure ZERODPI_RELEASE_STORE_FILE, "
            "ZERODPI_RELEASE_STORE_PASSWORD, ZERODPI_RELEASE_KEY_ALIAS, and "
            "optionally ZERODPI_RELEASE_KEY_PASSWORD for a signed release APK."
        )
    print(f"Android APK copied to: {packaged_apk}")
    return packaged_apk


def build_android_app_abi(
    abi: str,
    runtime: str,
    ndk_path: Path,
    android_api: int,
    dist_dir: Path,
) -> dict:
    arch, rust_target = ANDROID_APP_ABI_TARGETS[abi]
    print(f"\n--- Building Android app runtime ({runtime}, {abi}) ---")
    env = android_build_env(arch, rust_target, ndk_path, android_api)

    cargo_cmd = ["cargo", "build", "-p", "zerodpi", "--release", "--target", rust_target]
    if runtime == "rootless":
        cargo_cmd.append("--no-default-features")
    run(cargo_cmd, env=env)

    binary = REPO_ROOT / "target" / rust_target / "release" / "zerodpi"
    if not binary.exists():
        die(f"Expected binary not found: {binary}")

    standalone_dir = dist_dir / "bin" / abi
    standalone_dir.mkdir(parents=True, exist_ok=True)
    standalone_binary = standalone_dir / "zerodpi"
    copy_required_file(binary, standalone_binary)
    standalone_binary.chmod(0o755)

    jni_dir = dist_dir / "jniLibs" / abi
    jni_dir.mkdir(parents=True, exist_ok=True)
    native_artifact = jni_dir / "libzerodpi_exec.so"
    copy_required_file(binary, native_artifact)
    native_artifact.chmod(0o755)

    return {
        "abi": abi,
        "rustTarget": rust_target,
        "standaloneExecutable": str(standalone_binary.relative_to(dist_dir)).replace("\\", "/"),
        "nativeLibraryArtifact": str(native_artifact.relative_to(dist_dir)).replace("\\", "/"),
    }


def build_android_app_runtime(
    abi_arg: str,
    runtime_arg: str,
    android_ndk: str | None,
    android_api: int,
    build_type: str,
    android_gradle: str | None,
) -> None:
    abis = resolve_android_app_abis(abi_arg)
    runtimes = resolve_android_app_runtimes(runtime_arg)
    label = ", ".join(abis)
    runtime_label = ", ".join(runtimes)
    print(f"=== Building ZeroDPI Android app APK ({runtime_label}; {label}; {build_type}) ===")

    if android_api < ANDROID_DEFAULT_API_LEVEL:
        die(f"Android API level must be {ANDROID_DEFAULT_API_LEVEL} or newer.")

    rust_targets = sorted({ANDROID_APP_ABI_TARGETS[abi][1] for abi in abis})
    ensure_rustup_targets(rust_targets)

    ndk_path = resolve_android_ndk(android_ndk)
    for runtime in runtimes:
        dist_dir = REPO_ROOT / "dist" / "android-app" / runtime
        dist_dir.mkdir(parents=True, exist_ok=True)
        reset_android_app_runtime_inputs(dist_dir)
        copy_android_app_runtime_templates(dist_dir)

        entries = [
            build_android_app_abi(abi, runtime, ndk_path, android_api, dist_dir)
            for abi in abis
        ]
        write_android_app_manifest(dist_dir, runtime, android_api, entries)
        build_android_app_apk(runtime, dist_dir, build_type, android_gradle, ndk_path)
        print_android_app_contents(dist_dir)


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

def prompt_choice(question: str, choices: list, default: str) -> str:
    choices_str = [str(c) for c in choices]
    print(f"\n{question}")
    for i, choice in enumerate(choices_str, 1):
        print(f"  {i}) {choice}")
    while True:
        try:
            val = input(f"Select choice [default: {default}]: ").strip()
            if not val:
                return default
            if val.isdigit():
                idx = int(val) - 1
                if 0 <= idx < len(choices_str):
                    return choices_str[idx]
            if val in choices_str:
                return val
            print(f"Invalid choice. Please select 1-{len(choices_str)} or enter choice name.")
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)


def prompt_input(question: str, default: str | None = None) -> str:
    default_str = f" [default: {default}]" if default is not None else ""
    while True:
        try:
            val = input(f"{question}{default_str}: ").strip()
            if not val and default is not None:
                return default
            if val:
                return val
            print("Value cannot be empty.")
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)


def run_interactive() -> None:
    print("=" * 60)
    print("  ZeroDPI Interactive Builder")
    print("=" * 60)

    # 1. Platform selection
    platform_choices = ["linux", "windows", "termux", "android-app", "all"]
    # Detect host to set a smart default
    host_sys = platform.system()
    if host_sys == "Linux":
        default_platform = "linux"
    elif host_sys == "Windows":
        default_platform = "windows"
    else:
        default_platform = "all"
        
    selected_platform = prompt_choice("Select target build platform:", platform_choices, default_platform)

    # Initialize all potential variables with defaults
    windivert_version = WINDIVERT_DEFAULT_VERSION
    toolchain = WINDOWS_DEFAULT_TOOLCHAIN
    msys2_path = WINDOWS_DEFAULT_MSYS2_PATH
    linux_target = DEFAULT_LINUX_TARGET
    termux_arch = TERMUX_DEFAULT_ARCH
    android_ndk = None
    android_api = ANDROID_DEFAULT_API_LEVEL
    android_app_abi = "all"
    android_app_runtime = "rootless"
    android_app_build_type = "debug"
    android_gradle = None

    # Step-by-step questions based on selected platform
    if selected_platform == "linux":
        if platform.system() == "Windows":
            print("\nYou are building Linux binaries from Windows. We need to cross-compile.")
            target_choices = [DEFAULT_LINUX_TARGET] + [t for t in LINUX_CROSS_TARGETS if t != DEFAULT_LINUX_TARGET] + ["all", "Custom"]
            target_sel = prompt_choice("Select Linux target triple:", target_choices, DEFAULT_LINUX_TARGET)
            if target_sel == "Custom":
                linux_target = prompt_input("Enter custom Linux target triple (e.g. x86_64-unknown-linux-gnu):")
            else:
                linux_target = target_sel

            msys2_path = prompt_input("MSYS2 path for Zig compiler (if not on PATH):", WINDOWS_DEFAULT_MSYS2_PATH)
        else:
            print("\nYou are building natively on Linux. No extra cross-compilation variables needed.")

    elif selected_platform == "windows":
        windivert_version = prompt_input("WinDivert version to download/verify:", WINDIVERT_DEFAULT_VERSION)
        toolchain = prompt_input("Rust toolchain to use (press Enter for default, or empty for workspace default):", WINDOWS_DEFAULT_TOOLCHAIN)
        msys2_path = prompt_input("MSYS2 install path (required for GNU toolchain dlltool/ld):", WINDOWS_DEFAULT_MSYS2_PATH)

    elif selected_platform == "termux":
        arch_choices = list(TERMUX_ARCH_CHOICES) + ["Custom"]
        arch_sel = prompt_choice("Select Termux Android architecture:", arch_choices, TERMUX_DEFAULT_ARCH)
        if arch_sel == "Custom":
            termux_arch = prompt_input("Enter system architecture (e.g., aarch64, armv7):")
        else:
            termux_arch = arch_sel

        # Android NDK location
        default_ndk = os.environ.get("ANDROID_NDK_HOME", "")
        if not default_ndk:
            auto_ndk = _find_android_studio_ndk()
            if auto_ndk:
                default_ndk = str(auto_ndk)
        
        ndk_prompt = "Android NDK path (press Enter to auto-detect/download):"
        if default_ndk:
            android_ndk = prompt_input(ndk_prompt, default_ndk)
        else:
            ans = prompt_choice("Android NDK path selection:", ["Auto-detect or Download if missing", "Enter custom path"], "Auto-detect or Download if missing")
            if ans == "Enter custom path":
                android_ndk = prompt_input("Enter NDK path:")
            else:
                android_ndk = ""

        # Android API Level
        api_str = prompt_input("Android API level to use (>=23):", str(ANDROID_DEFAULT_API_LEVEL))
        android_api = int(api_str)

    elif selected_platform == "android-app":
        # Android ABI options
        abi_choices = ["all", "public", "debug", "Custom"]
        abi_sel = prompt_choice("Select Target APK Architecture ABIs:", abi_choices, "all")
        if abi_sel == "Custom":
            android_app_abi = prompt_input("Enter comma-separated list of ABIs (e.g. arm64-v8a,armeabi-v7a):")
        else:
            android_app_abi = abi_sel

        android_app_runtime = prompt_choice("Select App Runtime packet interception feature level:", list(ANDROID_APP_RUNTIME_CHOICES), "rootless")
        android_app_build_type = prompt_choice("Select Gradle build type:", list(ANDROID_APP_BUILD_TYPES), "debug")

        # Gradle command
        gradle_choices = ["Auto-detect default gradle wrapper/PATH", "Enter custom Gradle executable path"]
        gradle_sel = prompt_choice("Select Gradle wrapper / executable path option:", gradle_choices, "Auto-detect default gradle wrapper/PATH")
        if gradle_sel == "Enter custom Gradle executable path":
            android_gradle = prompt_input("Enter path to Gradle executable:")
        else:
            android_gradle = None

        # NDK Location
        default_ndk = os.environ.get("ANDROID_NDK_HOME", "")
        if not default_ndk:
            auto_ndk = _find_android_studio_ndk()
            if auto_ndk:
                default_ndk = str(auto_ndk)
        
        ndk_prompt = "Android NDK path (press Enter to auto-detect/download):"
        if default_ndk:
            android_ndk = prompt_input(ndk_prompt, default_ndk)
        else:
            ans = prompt_choice("Android NDK path selection:", ["Auto-detect or Download if missing", "Enter custom path"], "Auto-detect or Download if missing")
            if ans == "Enter custom path":
                android_ndk = prompt_input("Enter NDK path:")
            else:
                android_ndk = ""

        # API
        api_str = prompt_input("Android API level for NDK compilers (>=23):", str(ANDROID_DEFAULT_API_LEVEL))
        android_api = int(api_str)

    elif selected_platform == "all":
        windivert_version = prompt_input("WinDivert version to download/verify (Windows only):", WINDIVERT_DEFAULT_VERSION)
        toolchain = prompt_input("Rust toolchain to use for Windows target (press Enter for default):", WINDOWS_DEFAULT_TOOLCHAIN)
        msys2_path = prompt_input("MSYS2 install path (required for Windows GNU toolchain and Linux Zig cross-compiler):", WINDOWS_DEFAULT_MSYS2_PATH)

        target_choices = [DEFAULT_LINUX_TARGET] + [t for t in LINUX_CROSS_TARGETS if t != DEFAULT_LINUX_TARGET] + ["all", "Custom"]
        target_sel = prompt_choice("Select Linux targets to cross-compile:", target_choices, DEFAULT_LINUX_TARGET)
        if target_sel == "Custom":
            linux_target = prompt_input("Enter custom Linux target triple (e.g. x86_64-unknown-linux-gnu):")
        else:
            linux_target = target_sel

        arch_choices = list(TERMUX_ARCH_CHOICES) + ["Custom"]
        arch_sel = prompt_choice("Select Termux Android architecture to build:", arch_choices, TERMUX_DEFAULT_ARCH)
        if arch_sel == "Custom":
            termux_arch = prompt_input("Enter system architecture (e.g., aarch64, armv7):")
        else:
            termux_arch = arch_sel

        # Android NDK location
        default_ndk = os.environ.get("ANDROID_NDK_HOME", "")
        if not default_ndk:
            auto_ndk = _find_android_studio_ndk()
            if auto_ndk:
                default_ndk = str(auto_ndk)
        
        ndk_prompt = "Android NDK path (press Enter to auto-detect/download):"
        if default_ndk:
            android_ndk = prompt_input(ndk_prompt, default_ndk)
        else:
            ans = prompt_choice("Android NDK path selection:", ["Auto-detect or Download if missing", "Enter custom path"], "Auto-detect or Download if missing")
            if ans == "Enter custom path":
                android_ndk = prompt_input("Enter NDK path:")
            else:
                android_ndk = ""

        # Android API Level
        api_str = prompt_input("Android API level to use (>=23):", str(ANDROID_DEFAULT_API_LEVEL))
        android_api = int(api_str)

    # Let's confirm the plan and start building!
    print("\n" + "=" * 60)
    print("  CONFIRM ACTION PLAN")
    print("=" * 60)
    print(f"Platform:              {selected_platform}")
    if selected_platform in ("windows", "all"):
        print(f"WinDivert Version:     {windivert_version}")
        print(f"Windows Toolchain:     {toolchain or 'Workspace Default'}")
        print(f"MSYS2 Path:            {msys2_path}")
    if selected_platform == "linux" and platform.system() == "Windows":
        print(f"Linux Target:          {linux_target}")
        print(f"MSYS2 Path (for Zig):  {msys2_path}")
    if selected_platform == "all":
        print(f"Linux targets:         {linux_target}")
    if selected_platform in ("termux", "all"):
        print(f"Termux Architecture:   {termux_arch}")
        print(f"Android NDK:           {android_ndk or 'Auto-detect / Download'}")
        print(f"Android API level:     {android_api}")
    if selected_platform == "android-app":
        print(f"Android App ABIs:      {android_app_abi}")
        print(f"Android App Runtime:   {android_app_runtime}")
        print(f"App Build Type:        {android_app_build_type}")
        print(f"Gradle executable:     {android_gradle or 'Auto-detect'}")
        print(f"Android NDK:           {android_ndk or 'Auto-detect / Download'}")
        print(f"Android API level:     {android_api}")
    print("=" * 60)

    try:
        ans = input("\nProceed with this configuration? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(1)
    if ans not in ("", "y", "yes"):
        print("Aborted.")
        sys.exit(0)

    # Perform action based on selections
    if selected_platform == "linux":
        if platform.system() == "Windows":
            targets = resolve_linux_targets(linux_target)
            build_linux_cross_zigbuild(targets, msys2_path)
        else:
            build_linux()
    elif selected_platform == "windows":
        build_windows(windivert_version, toolchain, msys2_path)
    elif selected_platform == "termux":
        build_termux(termux_arch, android_ndk, android_api)
    elif selected_platform in ("android", "android-app"):
        build_android_app_runtime(
            android_app_abi,
            selected_platform if selected_platform != "android-app" else android_app_runtime,
            android_ndk,
            android_api,
            android_app_build_type,
            android_gradle,
        )
    elif selected_platform == "all":
        build_all(
            windivert_version,
            toolchain,
            msys2_path,
            termux_arch,
            android_ndk,
            android_api,
            resolve_linux_targets(linux_target),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build ZeroDPI for the current platform, Windows, Linux, Termux, or Android APK packaging.")
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Run the builder in interactive mode, prompting for options step-by-step.",
    )
    parser.add_argument(
        "--platform",
        "--target",
        dest="platform",
        choices=("auto", "linux", "windows", "termux", "android", "android-app", "all"),
        default="auto",
        help="Build platform (default: auto-detect host OS). Use 'android' or 'android-app' to build the APK.",
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
        help="Android NDK path for Termux and Android app runtime builds. Defaults to ANDROID_NDK_HOME.",
    )
    parser.add_argument(
        "--android-api",
        type=int,
        default=ANDROID_DEFAULT_API_LEVEL,
        metavar="LEVEL",
        help=f"Android API level for the NDK clang linker (Termux and Android app runtime, default: {ANDROID_DEFAULT_API_LEVEL}).",
    )
    parser.add_argument(
        "--android-app-abi",
        default="all",
        metavar="ABI",
        help=(
            "Android app ABI to build (default: all, meaning first-release "
            "public ABIs arm64-v8a and armeabi-v7a). Use 'debug' to also "
            "include x86_64, or pass a comma-separated ABI list."
        ),
    )
    parser.add_argument(
        "--android-app-runtime",
        choices=ANDROID_APP_RUNTIME_CHOICES,
        default="rootless",
        help=(
            "Android app runtime variant (default: rootless). 'rootless' "
            "builds without NFQUEUE packet interception; 'full' keeps the "
            "default packet-interception feature; 'both' builds both variants."
        ),
    )
    parser.add_argument(
        "--android-app-build-type",
        choices=ANDROID_APP_BUILD_TYPES,
        default="debug",
        help="Android app Gradle build type to assemble (default: debug).",
    )
    parser.add_argument(
        "--android-gradle",
        metavar="PATH",
        help=(
            "Gradle executable for Android APK builds. Defaults to android/gradlew "
            "if present, then compatible gradle on PATH, then a local Gradle "
            f"{ANDROID_GRADLE_FALLBACK_VERSION} download."
        ),
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

    if args.interactive or len(sys.argv) == 1:
        run_interactive()
        return

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
    elif selected_platform in ("android", "android-app"):
        build_android_app_runtime(
            args.android_app_abi,
            args.android_app_runtime,
            args.android_ndk,
            args.android_api,
            args.android_app_build_type,
            args.android_gradle,
        )
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
