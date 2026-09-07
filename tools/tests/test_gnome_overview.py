"""Hosted regression test for KI-0472: leave the overview, then activate.

Positive control: each assertion below is inverted at least once in this
file (an overview-open fixture must NOT report cleared; a located-window
fixture with the overview still open must NOT report activated), so a
helper that always returns True/False cannot pass silently.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pathlib import Path

from gnome_overview import overview_visible, overview_visible_pixels, overview_showing, pill_stats, search_pill_rect, window_activated  # noqa: E402

# Small synthetic OCR-text fixtures -- these are pure text/rect decision
# functions, so no image or tesseract dependency is needed to exercise them.
OVERVIEW_TEXT = "activities\n\ntype to search\n\n9:41 am"
OVERVIEW_TEXT_SPACED = "activities\n\nType   To   Search\n\n9:41 am"
DESKTOP_TEXT = "activities\n\nfiles  untitled - notepad\n\n9:41 am"
NOTEPAD_RECT = (100, 40, 700, 500)


def test_overview_text_is_visible():
    assert overview_visible(OVERVIEW_TEXT) is True


def test_overview_marker_tolerates_ocr_whitespace_noise():
    assert overview_visible(OVERVIEW_TEXT_SPACED) is True


def test_desktop_text_has_no_overview_marker():
    assert overview_visible(DESKTOP_TEXT) is False


def test_window_activated_requires_overview_cleared():
    assert window_activated(OVERVIEW_TEXT, NOTEPAD_RECT) is False


def test_window_activated_requires_a_located_rect():
    assert window_activated(DESKTOP_TEXT, None) is False


def test_window_activated_true_when_both_hold():
    assert window_activated(DESKTOP_TEXT, NOTEPAD_RECT) is True


FIXTURES = Path(__file__).parent / "fixtures"


def test_flat_dark_search_spot_means_overview():
    assert overview_visible_pixels(0.13, 0.0)
    assert overview_visible_pixels(0.25, 0.03)
    assert not overview_visible_pixels(0.26, 0.0)
    assert not overview_visible_pixels(0.13, 0.05)
    assert not overview_visible_pixels(1.0, 1.0)


def test_search_pill_rect_scales_with_the_frame():
    assert search_pill_rect(1024, 768) == (326, 44, 372, 40)
    left, top, w, h = search_pill_rect(2048, 1536)
    assert (left, top, w, h) == (652, 88, 744, 80)


def test_real_overview_probe_crop_reads_as_overview_and_wallpaper_does_not():
    # overview-search-pill.png is the search-entry crop of a real guest frame
    # (run 1618308) whose grey placeholder tesseract could not read; the
    # pixel marker must carry it. The wallpaper-like crop must not.
    pill = FIXTURES / "overview-search-pill.png"
    desktop = FIXTURES / "desktop-under-search-spot.png"
    mean, std = pill_stats(pill, rect=(0, 0, 372, 40))
    assert overview_showing("", mean, std), (mean, std)
    mean, std = pill_stats(desktop, rect=(0, 0, 372, 40))
    assert not overview_showing("", mean, std), (mean, std)
