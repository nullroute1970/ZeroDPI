"""Runtime data must travel alongside every packaged binary."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zerodpi_build", ROOT / "build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class RuntimePackagingTests(unittest.TestCase):
    def test_termux_finds_ndk_inside_sdk_without_app_project(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory) / "sdk"
            ndk = sdk / "ndk" / "27.2.12479018"
            (ndk / "toolchains" / "llvm").mkdir(parents=True)
            with (
                patch.dict(os.environ, {"ANDROID_HOME": str(sdk)}, clear=True),
                patch.object(Path, "home", return_value=Path(directory)),
            ):
                self.assertEqual(build._find_android_studio_ndk(), ndk)

    def test_common_packages_include_cloudflare_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build.copy_common_dist_files(output)
            self.assertEqual((ROOT / "cf.txt").read_bytes(), (output / "cf.txt").read_bytes())
            for name in ("config.toml", "sni_list.txt", "ip_list.txt"):
                self.assertTrue((output / name).is_file())

    def test_apk_platforms_are_rejected(self):
        for platform in ("android", "android-app"):
            with self.subTest(platform=platform):
                stderr = io.StringIO()
                arguments = ["build.py", "--platform", platform]
                with patch.object(sys, "argv", arguments), contextlib.redirect_stderr(stderr):
                    # Keep the pre-removal builder from downloading toolchains or running Gradle.
                    with patch.object(
                        build, "build_android_app_runtime", create=True,
                        side_effect=AssertionError("APK build was accepted"),
                    ):
                        with self.assertRaises(SystemExit) as stopped:
                            build.main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn("invalid choice", stderr.getvalue())

    def test_termux_dispatch_preserves_ndk_and_api_options(self):
        arguments = [
            "build.py", "--platform", "termux", "--termux-arch", "armv8",
            "--android-ndk", "/toolchains/ndk", "--android-api", "23",
        ]
        # Avoid a real cross-build/download; only the command-line dispatch is under test.
        with patch.object(sys, "argv", arguments), patch.object(build, "build_termux") as termux:
            build.main()
        termux.assert_called_once_with("armv8", "/toolchains/ndk", 23)


if __name__ == "__main__":
    unittest.main()
