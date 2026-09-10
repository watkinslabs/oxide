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
import tempfile
from pathlib import Path

TITLE_WORD = re.compile(r"notepad", re.IGNORECASE)
# OCR gives the title TEXT span, not the window frame: the frame's icon and
# minimize/maximize/close controls extend beyond the text on both sides.
# These margins are a heuristic bound on chrome width, not exact geometry.
LEFT_MARGIN = 220
RIGHT_MARGIN = 40
# A desktop-drawn frame is near-white; the wallpaper behind it is not. Every
# channel at or above this level counts as frame chrome.
FRAME_LEVEL = 200
# Rows of the title band to measure, relative to the title text's top: above
# it, through it (those rows hit glyphs and measure short), and below it.
TITLE_BAND = range(-10, 12)


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


def image_size(path):
    result = subprocess.run(["identify", "-format", "%w %h", str(path)], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
    width, _, height = result.stdout.strip().partition(" ")
    return int(width), int(height)


def frame_extent(image, centre_x, title_top):
    """Measure a window's frame from its chrome, or None when it is absent.

    Returns (left, right, bottom) of the near-white frame containing
    `centre_x` in the title band at `title_top`. The widest run across the
    band is the window's width: rows crossing the title glyphs measure short,
    rows above and below them measure the full frame. The bottom is where the
    frame's own column stops being chrome. A title word painted on the
    wallpaper rather than on a frame yields no run and answers None.
    """
    pixels = image.convert("RGB").load()
    width, height = image.size
    if not 0 <= centre_x < width:
        return None

    def chrome(x, y):
        return 0 <= x < width and 0 <= y < height and min(pixels[x, y]) >= FRAME_LEVEL

    best = None
    for offset in TITLE_BAND:
        y = title_top + offset
        if not chrome(centre_x, y):
            continue
        left = centre_x
        while chrome(left - 1, y): left -= 1
        right = centre_x
        while chrome(right + 1, y): right += 1
        if best is None or right - left > best[1] - best[0]:
            best = (left, right, y)
    if best is None:
        return None
    left, right, row = best
    # The centre column crosses the title glyphs, so measure the depth down
    # the outer frame edges. Inset columns cross the edit control's dark
    # border and would mistake its top for the window bottom.
    bottom = row
    for column in (left, right):
        depth = row
        while depth + 1 < height and chrome(column, depth + 1): depth += 1
        bottom = max(bottom, depth)
    return (left, right + 1, bottom + 1)

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
    width, height = image_size(path)
    left = max(0, min(lefts) - LEFT_MARGIN)
    right = min(width, max(rights) + RIGHT_MARGIN)
    top = max(0, title_top)
    bottom = height
    # The title text is centred in its frame, so projecting the window from
    # that text alone answers a rectangle narrower than the window: text the
    # application drew at the left of its client area then falls outside the
    # crop. Measure the frame itself when it can be measured.
    from PIL import Image
    with Image.open(path) as image:
        measured = frame_extent(image, (min(lefts) + max(rights)) // 2, title_top)
    if measured is not None:
        left, right, bottom = measured[0], measured[1], max(measured[2], top + 1)
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


# A menu bar sits within this many pixels of the top of the window frame.
MENU_BAND_DEPTH = 120


def menu_bar_word(path, rect, word):
    """The (left, top, width, height) of one menu-bar word inside `rect`.

    The bar is the topmost band of the window, so the match closest to the
    frame's top wins: a word of the same spelling in the document below it is
    not the menu item.
    """
    left, top, right, _ = rect
    best = None
    for text, wl, wt, ww, wh, _ in _tsv_words(path):
        if text.strip(".:").lower() != word.lower():
            continue
        if not (left <= wl and wl + ww <= right and top <= wt <= top + MENU_BAND_DEPTH):
            continue
        if best is None or wt < best[1]:
            best = (wl, wt, ww, wh)
    if best is not None:
        return best
    # Sparse full-frame OCR can discard the short, underlined menu glyphs.
    # Segment overlapping rows and enlarge them; require the complete menu
    # sequence on one OCR line before accepting coordinates from a crop.
    from PIL import Image
    captions = ("file", "edit", "format", "view", "help")
    scale, band, step = 3, 40, 20
    with Image.open(path) as image, tempfile.TemporaryDirectory(prefix="notepad-menu-") as directory:
        end = min(rect[3], top + MENU_BAND_DEPTH)
        for y in range(top, end, step):
            crop = image.crop((left, y, right, min(y + band, end)))
            target = Path(directory) / "band.png"
            crop.resize((crop.width * scale, crop.height * scale)).save(target)
            rows = list(_tsv_words(target))
            for key in dict.fromkeys(row[5] for row in rows):
                line = sorted((row for row in rows if row[5] == key), key=lambda row: row[1])
                if tuple(row[0].strip(".:").lower() for row in line) != captions:
                    continue
                for text, x, dy, width, height, _ in line:
                    if text.lower() == word.lower():
                        return left + x // scale, y + dy // scale, (width + scale - 1) // scale, (height + scale - 1) // scale
    return None
