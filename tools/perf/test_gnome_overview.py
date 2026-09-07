"""Overview decision from the guest's own frames: the check must be able to say
"overview" and able to say "not overview".

The numbers are the measured grey mean/standard deviation of the search-entry
crop of real 1024x768 acceptance screendumps: three frames that show the
Activities overview and three that show the Notepad window on the desktop. An
earlier rule (whole-entry crop, mean ceiling below the entry's own grey)
returned "not overview" for every one of them, so leaving the overview always
reported success and the run failed later for the wrong reason.
"""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from gnome_overview import (overview_showing, overview_visible, overview_visible_pixels,
                            search_pill_rect, window_activated)

# Measured on screen-*-locate-probe, screen-*-gnome-before-notepad and
# screen-*-launch-overview-probe.
OVERVIEW_PIXELS = (0.2524, 0.0000)
# Measured on screen-*-activation-overview-probe, screen-*-activated and
# screen-*-after-token: the Notepad window covers the entry's spot.
DESKTOP_PIXELS = (0.0693, 0.0034)


class OverviewPixelDecision(unittest.TestCase):
    def test_guest_overview_frames_read_as_the_overview(self):
        self.assertTrue(overview_visible_pixels(*OVERVIEW_PIXELS))

    def test_guest_desktop_frames_do_not_read_as_the_overview(self):
        self.assertFalse(overview_visible_pixels(*DESKTOP_PIXELS))

    def test_a_textured_spot_is_not_the_flat_entry(self):
        mean, _ = OVERVIEW_PIXELS
        self.assertFalse(overview_visible_pixels(mean, 0.2))

    def test_crop_excludes_the_placeholder_text_and_icon(self):
        left, top, width, height = search_pill_rect(1024, 768)
        # The magnifier icon and the placeholder text occupy the entry's left
        # side; measuring them is what made the decision unable to fire.
        self.assertGreaterEqual(left, 640)
        self.assertLessEqual(left + width, 696)
        self.assertGreaterEqual(top, 46)
        self.assertLessEqual(top + height, 82)

    def test_either_marker_suffices_and_ocr_still_counts(self):
        self.assertTrue(overview_showing("type to search", *DESKTOP_PIXELS))
        self.assertTrue(overview_showing("", *OVERVIEW_PIXELS))
        self.assertFalse(overview_showing("", *DESKTOP_PIXELS))

    def test_activation_needs_a_located_window_and_no_overview_text(self):
        self.assertTrue(window_activated("notepad", (1, 2, 3, 4)))
        self.assertFalse(window_activated("notepad", None))
        self.assertFalse(window_activated("type to search", (1, 2, 3, 4)))
        self.assertFalse(overview_visible("notepad"))


if __name__ == "__main__":
    unittest.main()
