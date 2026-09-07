"""Hosted regression test for KI-0472: leave the overview, then activate.

Positive control: each assertion below is inverted at least once in this
file (an overview-open fixture must NOT report cleared; a located-window
fixture with the overview still open must NOT report activated), so a
helper that always returns True/False cannot pass silently.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gnome_overview import overview_visible, window_activated  # noqa: E402

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
