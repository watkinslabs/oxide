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
