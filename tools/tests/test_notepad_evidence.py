"""Hosted regression test for KI-0435: A3 token check must locate Notepad.

Positive control: `notepad-fail-overview.png` and the real run-94582 fixture
(GNOME overview, no Notepad window) must FAIL (found=False). The synthetic
`notepad-pass.png` (a genuine "Untitled - Notepad" title with the token in
its client area) must PASS. `notepad-token-outside-window.png` proves a
Notepad title elsewhere on screen does not launder a token typed outside
its window.
"""
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from notepad_evidence import token_in_notepad_window  # noqa: E402


def test_run_94582_regression_fails(tmp_path):
    """Real KI-0435 evidence: token landed in GNOME overview, not Notepad."""
    found, rect = token_in_notepad_window(FIXTURES / "ki0435-run94582-after-token.png", "oxide-94582",
                                          crop_path=tmp_path / "crop.png")
    assert found is False
    assert rect is None


def test_synthetic_overview_fails(tmp_path):
    found, rect = token_in_notepad_window(FIXTURES / "notepad-fail-overview.png", "oxide-fixture-pass",
                                          crop_path=tmp_path / "crop.png")
    assert found is False
    assert rect is None


def test_synthetic_notepad_window_passes(tmp_path):
    found, rect = token_in_notepad_window(FIXTURES / "notepad-pass.png", "oxide-fixture-pass",
                                          crop_path=tmp_path / "crop.png")
    assert found is True
    assert rect is not None


def test_token_outside_located_window_fails(tmp_path):
    """A Notepad title is on screen, but the token was typed elsewhere."""
    found, _ = token_in_notepad_window(FIXTURES / "notepad-token-outside-window.png", "oxide-fixture-elsewhere",
                                       crop_path=tmp_path / "crop.png")
    assert found is False
