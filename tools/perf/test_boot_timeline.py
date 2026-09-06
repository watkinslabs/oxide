import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("boot_timeline", Path(__file__).with_name("boot-timeline.py"))
timeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timeline)


class BootTimelineTests(unittest.TestCase):
    def test_shell_starting_session_and_started_are_distinct(self):
        report = timeline.parse("\n".join([
            "[18.756] gnome-shell[392]: Running GNOME Shell (using mutter 48.8)",
            "[25.202] gnome-session-binary[368]: Entering running state",
            "[45.380] gnome-shell[392]: GNOME Shell started at Sat Sep 05",
        ]))
        self.assertEqual(report["milestones"], {
            "shell_starting": 18.756, "session_running": 25.202, "shell_started": 45.380})

    def test_graphical_target_does_not_establish_desktop_readiness(self):
        report = timeline.parse("[80.924] systemd[1]: Reached target graphical.target - Graphical Interface.")
        self.assertEqual(report["milestones"], {"graphical_target": 80.924})
        self.assertNotIn("session_running", report["milestones"])

    def test_overlapping_units_and_manager_scopes_remain_separate(self):
        report = timeline.parse("\n".join([
            "[1.000] systemd[1]: Starting a.service - A...",
            "[2.000] systemd[40]: Starting a.service - A...",
            "[3.000] systemd[1]: Starting b.service - B...",
            "[4.000] systemd[40]: Started a.service - A.",
            "[5.000] systemd[1]: Finished b.service - B.",
            "[6.000] systemd[1]: Finished a.service - A.",
        ]))
        self.assertEqual([(unit["manager"], unit["seconds"]) for unit in report["units"]],
                         [("1", 5.0), ("40", 2.0), ("1", 2.0)])
        self.assertEqual(report["unfinished"], [])

    def test_system_startup_is_not_a_desktop_session(self):
        report = timeline.parse("\n".join([
            "[14.769] systemd[1]: Reached target graphical.target - Graphical Interface.",
            "[15.599] systemd[1]: Startup finished in 4s (kernel) + 11s (userspace).",
        ]))
        self.assertEqual(report["milestones"], {
            "graphical_target": 14.769, "system_startup_finished": 15.599})
        self.assertNotIn("session_running", report["milestones"])

    def test_user_manager_startup_does_not_claim_system_startup(self):
        report = timeline.parse("[15.000] systemd[999]: Startup finished in 1s.")
        self.assertNotIn("system_startup_finished", report["milestones"])

    def test_restarted_unit_uses_its_latest_start(self):
        report = timeline.parse("\n".join([
            "[1.000] systemd[1]: Starting a.service - A...",
            "[2.000] systemd[1]: Failed to start a.service - A.",
            "[3.000] systemd[1]: Starting a.service - A...",
            "[5.000] systemd[1]: Started a.service - A.",
        ]))
        self.assertEqual([unit["seconds"] for unit in report["units"]], [2.0, 1.0])

    def test_multiple_boots_rejected(self):
        with self.assertRaises(ValueError):
            timeline.parse("[90.000] end\n[1.000] reboot")


if __name__ == "__main__":
    unittest.main()
