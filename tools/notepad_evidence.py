"""Notepad-window location and in-window OCR for the acceptance harness.

KI-0435: a bare screenshot-diff + full-frame OCR check passes when the
injected token lands in GNOME's overview search box (or any other focused
text field) instead of Notepad's client area. These functions locate the
guest's Notepad window by OCR'ing its title-bar text and restrict the token
check to a crop derived from that location, so a token typed anywhere else
on screen fails.
"""
import re
import subprocess
from pathlib import Path

TITLE_WORD = re.compile(r"notepad", re.IGNORECASE)
# OCR gives the title TEXT span, not the window frame: the frame's icon and
# minimize/maximize/close controls extend beyond the text on both sides.
# These margins are a heuristic bound on chrome width, not exact geometry.
LEFT_MARGIN = 220
RIGHT_MARGIN = 40


def _tsv_words(path):
    """Yield (text, left, top, width, height, line_key) per OCR'd word."""
    result = subprocess.run(["tesseract", str(path), "stdout", "--psm", "11", "tsv"],
                            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=20)
    lines = result.stdout.splitlines()
    if len(lines) < 2:
        return
    header = lines[0].split("\t")
    for row in lines[1:]:
        cells = row.split("\t")
        if len(cells) != len(header):
            continue
        record = dict(zip(header, cells))
        text = record.get("text", "").strip()
        if not text:
            continue
        try:
            left, top, width, height = (int(record[key]) for key in ("left", "top", "width", "height"))
        except (KeyError, ValueError):
            continue
        line_key = (record.get("block_num"), record.get("par_num"), record.get("line_num"))
        yield text, left, top, width, height, line_key


def _image_size(path):
    result = subprocess.run(["identify", "-format", "%w %h", str(path)], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
    width, _, height = result.stdout.strip().partition(" ")
    return int(width), int(height)


def locate_notepad_window(path):
    """Return (left, top, right, bottom) of the Notepad window, or None.

    Finds the OCR word "Notepad" (from a title reading "Untitled - Notepad"
    or similar), widens to the full title-bar text line for a left/right
    span, then projects a window rectangle from the title line's vertical
    position down to the image bottom, widened by a fixed margin to cover
    frame chrome the title text itself does not include. Returns None when
    no window title is found anywhere in the image -- the case that must
    fail the A3 check, since no Notepad window is on screen at all.
    """
    words = list(_tsv_words(path))
    title_words = [word for word in words if TITLE_WORD.search(word[0])]
    if not title_words:
        return None
    _, _, title_top, _, _, title_line = title_words[0]
    line_words = [word for word in words if word[5] == title_line]
    lefts = [word[1] for word in line_words]
    rights = [word[1] + word[3] for word in line_words]
    width, height = _image_size(path)
    left = max(0, min(lefts) - LEFT_MARGIN)
    right = min(width, max(rights) + RIGHT_MARGIN)
    top = max(0, title_top)
    bottom = height
    if left >= right or top >= bottom:
        return None
    return (left, top, right, bottom)


def crop_image(path, rect, out_path):
    left, top, right, bottom = rect
    subprocess.run(["convert", str(path), "-crop", f"{right - left}x{bottom - top}+{left}+{top}",
                    "+repage", str(out_path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def ocr_text(path):
    result = subprocess.run(["tesseract", str(path), "stdout"], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=20)
    return re.sub(r"[^a-z0-9-]", "", result.stdout.lower())


def token_in_notepad_window(path, token, crop_path=None):
    """True only if `token` OCRs inside the located Notepad window crop.

    Returns (found, rect). `found` is False whenever no Notepad window
    title is located in `path`, even if `token` appears elsewhere in the
    frame (GNOME overview search, a stray focused field, ...); `rect` is
    None in that case so the caller can report why.
    """
    rect = locate_notepad_window(path)
    if rect is None:
        return False, None
    target = Path(crop_path) if crop_path else Path(f"{path}.notepad-crop.png")
    crop_image(path, rect, target)
    return token in ocr_text(target), rect
