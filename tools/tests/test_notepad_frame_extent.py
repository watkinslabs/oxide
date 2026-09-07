"""The window a screenshot check crops is measured, not projected.

A title is centred in its frame, so a rectangle projected from the title
text alone is narrower than the window and hides whatever the application
drew at the left of its client area. These cases pin the measurement of the
frame itself; each assertion below has its opposite in the same file, so a
helper that always answers the same thing cannot pass.
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from notepad_evidence import frame_extent  # noqa: E402

WALLPAPER = (24, 22, 30)
CHROME = (255, 255, 255)
STATUS = (212, 208, 200)
GLYPH = (51, 51, 55)
FRAME = (148, 110, 877, 692)
TITLE_TOP = 122


def frame_image(title_glyphs=True, status_bar=True):
    """A wallpaper with one light window on it, as the desktop draws one."""
    image = Image.new("RGB", (1024, 768), WALLPAPER)
    draw = ImageDraw.Draw(image)
    left, top, right, bottom = FRAME
    draw.rectangle((left, top, right - 1, bottom - 1), fill=CHROME)
    if status_bar:
        draw.rectangle((left, bottom - 20, right - 1, bottom - 1), fill=STATUS)
    if title_glyphs:
        # The centred title text, which crosses the frame's centre column.
        draw.rectangle((479, TITLE_TOP, 544, TITLE_TOP + 11), fill=GLYPH)
    return image


def test_the_frame_is_measured_not_projected_from_its_title():
    left, right, bottom = frame_extent(frame_image(), 512, TITLE_TOP)
    assert (left, right) == (FRAME[0], FRAME[2])


def test_the_title_glyphs_do_not_shorten_the_measurement():
    with_text = frame_extent(frame_image(title_glyphs=True), 512, TITLE_TOP)
    without_text = frame_extent(frame_image(title_glyphs=False), 512, TITLE_TOP)
    assert with_text == without_text


def test_the_depth_reaches_the_status_bar_at_the_frame_bottom():
    _, _, bottom = frame_extent(frame_image(), 512, TITLE_TOP)
    assert bottom == FRAME[3]
    # A frame whose bottom row is chrome rather than status grey measures the
    # same depth: the two colours are both frame, neither is wallpaper.
    assert frame_extent(frame_image(status_bar=False), 512, TITLE_TOP)[2] == FRAME[3]


def test_a_title_painted_on_the_wallpaper_measures_no_frame():
    image = Image.new("RGB", (1024, 768), WALLPAPER)
    assert frame_extent(image, 512, TITLE_TOP) is None


def test_a_centre_outside_the_image_measures_nothing():
    assert frame_extent(frame_image(), 4096, TITLE_TOP) is None
