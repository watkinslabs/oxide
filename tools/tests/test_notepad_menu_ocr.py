"""Real menu glyph regression; document text cannot substitute for a menu."""
import sys
from pathlib import Path
from PIL import Image
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from notepad_evidence import menu_bar_word

FIXTURE = Path(__file__).parent / 'fixtures/ki0925-notepad-menu.png'
RECT = (0, 0, 729, 570)


def test_real_underlined_menu():
    item = menu_bar_word(FIXTURE, RECT, 'File')
    assert item is not None
    x, y, w, h = item
    assert 5 <= x <= 10 and 27 <= y <= 33 and 20 <= w <= 30 and 6 <= h <= 12


def test_document_does_not_replace_missing_menu(tmp_path):
    with Image.open(FIXTURE) as image:
        image.paste((212, 208, 200), (0, 22, 729, 44))
        path = tmp_path / 'no-menu.png'
        image.save(path)
    assert menu_bar_word(path, RECT, 'File') is None
