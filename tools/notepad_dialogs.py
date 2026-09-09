"""Visible dialog and file round-trip checks for the Notepad acceptance run."""
import re
import time
from pathlib import Path
from notepad_evidence import _tsv_words, frame_extent, crop_image, menu_bar_word

PAINT_SECONDS = 30


def words(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def dialog_rect(path, title):
    """Locate a titled dialog, requiring measured chrome around its title."""
    from PIL import Image
    rows = list(_tsv_words(path))
    for key in dict.fromkeys(row[5] for row in rows):
        line = [row for row in rows if row[5] == key]
        if words(" ".join(row[0] for row in line)) != words(title):
            continue
        left = min(row[1] for row in line)
        right = max(row[1] + row[3] for row in line)
        top = min(row[2] for row in line)
        with Image.open(path) as image:
            frame = frame_extent(image, (left + right) // 2, top)
        if frame is not None and frame[2] > top + 40:
            return frame[0], top, frame[1], frame[2]
    return None


def control_word(path, rect, caption):
    """Require a caption below the title, wholly inside the dialog."""
    left, top, right, bottom = rect
    for text, x, y, width, height, _ in _tsv_words(path):
        if words(text) == words(caption) and left <= x and x + width <= right \
                and top + 20 < y and y + height <= bottom:
            return x + width // 2, y + height // 2
    return None


class DialogChecks:
    def __init__(self, runner, conn, deadline, guest=None):
        self.runner, self.conn, self.deadline, self.guest = runner, conn, deadline, guest

    def key(self, *names):
        self.runner.keys_immediate(self.conn, *names)

    def wait(self, label, predicate):
        end = min(self.deadline, time.monotonic() + PAINT_SECONDS)
        while True:
            if self.guest is not None and self.guest.poll() is not None:
                self.runner.die(f"QEMU exited during {label}")
            path, _ = self.runner.screenshot(self.conn, label)
            result = predicate(path)
            if result:
                return path, result
            if time.monotonic() >= end:
                self.runner.die(f"{label} was not visibly verified; retained {path}")
            time.sleep(0.25)

    def dialog(self, label, title, captions):
        def painted(path):
            rect = dialog_rect(path, title)
            if rect is None:
                return None
            if not all(control_word(path, rect, caption) for caption in captions):
                return None
            crop_image(path, rect, Path(f"{self.runner.SCREEN}-{label}-dialog.png"))
            return rect
        return self.wait(label, painted)

    def click_caption(self, path, rect, caption):
        point = control_word(path, rect, caption)
        if point is None:
            self.runner.die(f"{caption} caption absent inside dialog {rect}")
        width, height = self.runner.image_size(path)
        self.runner.click(self.conn, *point, width, height)

    def document(self, label, text):
        def painted(path):
            rect = self.runner.locate_notepad_window(path)
            if rect is None:
                return False
            # Exclude the title and menu: a filename containing the token is
            # not evidence that the edit control loaded the saved contents.
            left, top, right, bottom = rect
            menu = menu_bar_word(path, rect, "File")
            if menu is None:
                return False
            client = (left, menu[1] + menu[3], right, bottom)
            if client[1] >= bottom:
                return False
            crop = Path(f"{self.runner.SCREEN}-{label}-document.png")
            crop_image(path, client, crop)
            return text in self.runner.ocr(crop)
        return self.wait(label, painted)

    def filename(self, value):
        self.key("alt", "n")
        self.key("ctrl", "a")
        punctuation = {":": ("shift", "semicolon"), "\\": ("backslash",), ".": ("dot",), "-": ("minus",)}
        for char in value:
            self.key(*punctuation.get(char, (char,)))

    def run(self):
        r = self.runner
        self.key("alt", "h")
        self.wait("help-menu", lambda path: "about" in words(r.ocr_raw(path)))
        self.key("a")
        path, rect = self.dialog("about", "About Notepad", ("OK", "license"))
        self.click_caption(path, rect, "OK")
        self.wait("about-closed", lambda path: dialog_rect(path, "About Notepad") is None)
        self.document("after-about", r.TOKEN)

        # Ctrl+S on an untitled document must open Save As.
        self.key("ctrl", "s")
        path, rect = self.dialog("save-as", "Save As", ("Save", "Cancel"))
        # Open the file-type combo using its mnemonic, then the standard
        # combo shortcut; require the second filter, not just the closed value.
        self.key("alt", "t")
        self.key("alt", "down")
        self.wait("save-type-dropdown", lambda path: self.dropdown(path, "Save As"))
        self.key("esc")
        filename = f"z:\\tmp\\notepad-{r.RUN}.txt"
        self.filename(filename)
        path, rect = self.dialog("save-filename", "Save As", ("Save", "Cancel"))
        self.click_caption(path, rect, "Save")
        self.wait("saved", lambda path: dialog_rect(path, "Save As") is None
                  and f"notepad-{r.RUN}" in r.ocr(path))
        # Change the document and save again to exercise Save on a named file.
        updated = r.TOKEN + "-saved"
        self.key("ctrl", "a")
        r.type_text(self.conn, updated)
        self.document("edited-before-save", updated)
        self.key("ctrl", "s")
        self.key("ctrl", "n")
        self.wait("new-document", lambda path: "untitled" in words(r.ocr_raw(path))
                  and updated not in r.ocr(path))
        self.key("ctrl", "o")
        path, rect = self.dialog("open", "Open", ("Open", "Cancel"))
        self.key("alt", "t")
        self.key("alt", "down")
        self.wait("open-type-dropdown", lambda path: self.dropdown(path, "Open"))
        self.key("esc")
        self.filename(filename)
        path, rect = self.dialog("open-filename", "Open", ("Open", "Cancel"))
        self.click_caption(path, rect, "Open")
        self.wait("open-closed", lambda path: dialog_rect(path, "Open") is None)
        self.document("reopened-document", updated)
        # Exercise both Cancel buttons with a clean, named document.
        self.key("alt", "f")
        self.key("a")
        path, rect = self.dialog("save-as-cancel", "Save As", ("Save", "Cancel"))
        self.click_caption(path, rect, "Cancel")
        self.wait("save-as-cancelled", lambda path: dialog_rect(path, "Save As") is None)
        self.key("ctrl", "o")
        path, rect = self.dialog("open-cancel", "Open", ("Open", "Cancel"))
        self.click_caption(path, rect, "Cancel")
        self.wait("open-cancelled", lambda path: dialog_rect(path, "Open") is None)
        self.document("after-dialog-cancel", updated)
        print("windows-notepad-acceptance: dialogs PASS (About, captions, Save As, Save, Open, file types, Cancel, content round trip)")

    def dropdown(self, path, title):
        rect = dialog_rect(path, title)
        if rect is None:
            return False
        crop = Path(f"{self.runner.SCREEN}-file-types.png")
        crop_image(path, rect, crop)
        text = words(self.runner.ocr_raw(crop))
        return "all" in text and "files" in text and "text" in text
