import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "probe-target-directory.py"


class ProbeTargetDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oxide probe workspace ")
        self.workspace = Path(self.tmp.name) / "workspace with spaces"
        (self.workspace / "src").mkdir(parents=True)
        (self.workspace / "Cargo.toml").write_text(
            "[package]\nname = 'probe_fixture'\nversion = '0.1.0'\nedition = '2021'\n"
            "[lib]\npath = 'src/lib.rs'\n"
        )
        (self.workspace / "src/lib.rs").write_text("pub fn fixture() {}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def resolve(self, env=None):
        child_env = os.environ.copy()
        child_env.pop("CARGO_TARGET_DIR", None)
        if env:
            child_env.update(env)
        return subprocess.run(
            ["python3", str(SCRIPT), "--workspace", str(self.workspace)],
            cwd=ROOT.parent,
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_target(self, result, expected):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(expected.resolve()) + "\n")

    def test_absolute_environment_target_directory(self):
        target = self.workspace / "absolute target with spaces"
        self.assert_target(self.resolve({"CARGO_TARGET_DIR": str(target)}), target)

    def test_relative_environment_target_directory(self):
        target = self.workspace / "relative target"
        self.assert_target(self.resolve({"CARGO_TARGET_DIR": "relative target"}), target)

    def test_local_cargo_config_target_directory(self):
        cargo = self.workspace / ".cargo"
        cargo.mkdir()
        (cargo / "config.toml").write_text("[build]\ntarget-dir = 'configured target'\n")
        self.assert_target(self.resolve(), self.workspace / "configured target")

    def test_metadata_failure_is_not_default_target_fallback(self):
        (self.workspace / "Cargo.toml").write_text("this is not Cargo TOML\n")
        result = self.resolve({"CARGO_TARGET_DIR": str(self.workspace / "ignored target")})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(str(self.workspace / "target"), result.stdout)


if __name__ == "__main__":
    unittest.main()
