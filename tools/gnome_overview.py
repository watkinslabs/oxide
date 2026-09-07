"""GNOME overview / window-activation decision helpers for the Notepad
acceptance harness.

KI-0472: the guest desktop session starts inside the Activities overview.
Launching Notepad while the overview is showing renders the window only
as an overview thumbnail; the injected acceptance token then lands in
the overview's own "Type to search" entry instead of Notepad's client
area (A3 correctly fails, but for the wrong reason -- the harness never
left the overview). These are pure text/rect decision functions, kept
separate from the QMP transport and tesseract subprocess calls so they
are unit-testable without a live guest or an image file.
"""
import re
import subprocess

OVERVIEW_MARKER = re.compile(r"type\s+to\s+search", re.IGNORECASE)


def overview_visible(text):
    """True if the Activities overview search placeholder is on screen.

    `text` is raw (whitespace-preserving) OCR output of a full-frame
    screenshot. The overview's "Type to search" placeholder only renders
    while the overview is showing; GNOME's top-bar Activities button
    text is present in both states and is not used as the marker.
    """
    return OVERVIEW_MARKER.search(text) is not None


def window_activated(text, window_rect):
    """True once the overview has cleared and a window rect was located.

    `window_rect` is a `locate_notepad_window`-shaped result: None means
    no window title was found anywhere on screen, which can never count
    as activated regardless of overview state. `text` is the same
    full-frame OCR text `overview_visible` consumes.
    """
    return window_rect is not None and not overview_visible(text)


# The overview's search entry is a uniform rounded box at the top centre of
# the frame; its grey placeholder text defeats OCR at the guest's 1024x768, so
# the pixel statistics of that box are the marker. The crop is the entry's
# right-hand interior, past the magnifier icon and past the placeholder text:
# measuring the whole entry measures its own text, whose contrast makes the
# box read as neither flat nor uniformly grey and made this decision one that
# could never say "overview" at all. Fractions of the frame so any resolution
# maps to the same spot.
SEARCH_PILL_LEFT = 660 / 1024
SEARCH_PILL_TOP = 52 / 768
SEARCH_PILL_WIDTH = 30 / 1024
SEARCH_PILL_HEIGHT = 24 / 768
# The entry's own grey, as a band: a wallpaper or a window under that spot is
# darker or brighter than the entry, and neither is this flat. A ceiling alone
# admits every dark window, and a ceiling below the entry's grey admits
# nothing at all.
# Measured interiors: run 1618308 fixture 0.134, runs 26893/458537 0.252;
# the wallpaper under the spot on the bare desktop reads 0.069 (std 0.003).
PILL_MEAN_MIN = 0.12
PILL_MEAN_MAX = 0.32
PILL_STD_MAX = 0.03


def search_pill_rect(width, height):
    """Pixel rect (left, top, w, h) of the overview search entry for a frame."""
    return (int(width * SEARCH_PILL_LEFT), int(height * SEARCH_PILL_TOP),
            max(1, int(width * SEARCH_PILL_WIDTH)), max(1, int(height * SEARCH_PILL_HEIGHT)))


def overview_visible_pixels(mean, std):
    """True when the search-entry spot is the entry's own flat grey.

    `mean`/`std` are the grey-level mean and standard deviation, in [0, 1],
    of the `search_pill_rect` crop of a full-frame screenshot.
    """
    return PILL_MEAN_MIN <= mean <= PILL_MEAN_MAX and std <= PILL_STD_MAX


def overview_showing(text, mean, std):
    """Either marker suffices: OCR'd placeholder text or the flat dark entry."""
    return overview_visible(text) or overview_visible_pixels(mean, std)


def image_size(path):
    result = subprocess.run(["identify", "-format", "%w %h", str(path)], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
    width, _, height = result.stdout.strip().partition(" ")
    return int(width), int(height)


def pill_stats(path, rect=None):
    """Grey mean/std of the overview search-entry spot of a full-frame image
    (or of `rect`, for a pre-cropped fixture). Unreadable images report
    (1.0, 1.0), which never counts as the overview."""
    if rect is None:
        width, height = image_size(path)
        rect = search_pill_rect(width, height)
    left, top, w, h = rect
    result = subprocess.run(["convert", str(path), "-crop", f"{w}x{h}+{left}+{top}", "+repage",
                             "-colorspace", "gray", "-format", "%[fx:mean] %[fx:standard_deviation]", "info:"],
                            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=20)
    parts = result.stdout.split()
    if len(parts) != 2:
        return 1.0, 1.0
    return float(parts[0]), float(parts[1])
