import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("gnome_verifier",
    Path(__file__).resolve().parents[2] / "scratch/verify-gnome-candidate.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class FrameWaitTests(unittest.TestCase):
    def test_delayed_render_is_not_an_early_failure(self):
        runner = Mock()
        runner.screenshot.side_effect = [("frame", "console")] * 4 + [("frame", "desktop")]
        with patch.object(verifier.time, "monotonic", return_value=0):
            result = verifier.wait_changed_frame(runner, None, None, None, None,
                                                  "console", 100, "response")
        self.assertEqual(result, ("frame", "desktop"))
        self.assertEqual(runner.uart_pump.call_count, 4)
        runner.die.assert_not_called()

    def test_deadline_without_change_fails(self):
        runner = Mock()
        runner.die.side_effect = SystemExit(1)
        with patch.object(verifier.time, "monotonic", return_value=100):
            with self.assertRaises(SystemExit):
                verifier.wait_changed_frame(runner, None, None, None, None,
                                              "console", 100, "response")
        runner.screenshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
