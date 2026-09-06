"""Acceptance must retain GNOME evidence before starting the PE workload."""
import importlib.util
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SPEC = importlib.util.spec_from_file_location(
    "notepad_acceptance", Path(__file__).resolve().parents[1] / "windows-notepad-acceptance.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class DesktopOrderTests(unittest.TestCase):
    def test_launch_follows_session_and_retained_frame(self):
        events = []
        uart = Mock()
        uart.sendall.side_effect = lambda command: events.append(command)
        with patch.object(runner, "wait_marker", side_effect=lambda *args: events.append(args[3])), \
             patch.object(runner, "wait_for_rendered_desktop", side_effect=lambda *args: events.append("rendered-desktop")), \
             patch.object(runner, "screenshot", side_effect=lambda _, label: events.append(label)):
            runner.launch_on_desktop(uart, bytearray(), None, None, 1)
        self.assertEqual(events, ["sh-5.2#", "Entering running state",
                                  "rendered-desktop",
                                  "gnome-before-notepad", runner.DESKTOP_LAUNCH])
        self.assertIn(b'nsenter --target "$1" --env', runner.DESKTOP_LAUNCH)
        self.assertNotIn(b'DISPLAY=:', runner.DESKTOP_LAUNCH)

    def test_missing_session_does_not_launch(self):
        uart = Mock()
        with patch.object(runner, "wait_marker", side_effect=[None, SystemExit(1)]), \
             patch.object(runner, "screenshot") as frame:
            with self.assertRaises(SystemExit):
                runner.launch_on_desktop(uart, bytearray(), None, None, 1)
        uart.sendall.assert_not_called()
        frame.assert_not_called()

    def test_failed_frame_capture_does_not_launch(self):
        uart = Mock()
        with patch.object(runner, "wait_marker"), \
             patch.object(runner, "wait_for_rendered_desktop"), \
             patch.object(runner, "screenshot", side_effect=SystemExit(1)):
            with self.assertRaises(SystemExit):
                runner.launch_on_desktop(uart, bytearray(), None, None, 1)
        uart.sendall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
