"""Runtime data must travel alongside every packaged binary."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zerodpi_build", ROOT / "build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class RuntimePackagingTests(unittest.TestCase):
    def test_common_packages_include_cloudflare_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build.copy_common_dist_files(output)
            self.assertEqual((ROOT / "cf.txt").read_bytes(), (output / "cf.txt").read_bytes())
            for name in ("config.toml", "sni_list.txt", "ip_list.txt"):
                self.assertTrue((output / name).is_file())

    def test_android_runtime_assets_include_cloudflare_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build.copy_android_app_runtime_templates(output)
            self.assertEqual((ROOT / "cf.txt").read_bytes(), (output / "assets/zerodpi/cf.txt").read_bytes())


if __name__ == "__main__":
    unittest.main()
