"""Reject absent captions and title-only save/load evidence without a boot."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import notepad_dialogs as dialogs
from notepad_evidence import ocr_text


class DialogEvidenceTests(unittest.TestCase):
    def test_title_or_background_text_cannot_stand_in_for_button_caption(self):
        rows = [
            ("Open", 120, 100, 40, 15, (1, 1, 1)),
            ("Open", 10, 190, 40, 15, (2, 1, 1)),
            ("Open", 160, 390, 40, 15, (3, 1, 1)),
        ]
        with patch.object(dialogs, "_tsv_words", return_value=rows):
            self.assertIsNone(dialogs.control_word("screen", (100, 100, 400, 350), "Open"))
        rows.append(("Open", 320, 290, 40, 15, (4, 1, 1)))
        with patch.object(dialogs, "_tsv_words", return_value=rows):
            self.assertEqual(dialogs.control_word("screen", (100, 100, 400, 350), "Open"), (340, 297))

    def test_saved_filename_cannot_prove_loaded_document_contents(self):
        from PIL import Image, ImageDraw, ImageFont
        font = ImageFont.truetype("DejaVuSans.ttf", 22)
        with tempfile.TemporaryDirectory(prefix="B3630-dialog-test-") as tmp:
            path = Path(tmp) / "screen.png"
            image = Image.new("RGB", (600, 350), "white")
            draw = ImageDraw.Draw(image)
            draw.text((30, 10), "oxide-proof - Notepad", font=font, fill="black")
            draw.text((30, 36), "File  Edit  Format  View  Help", font=font, fill="black")
            image.save(path)
            runner = SimpleNamespace(SCREEN=Path(tmp) / "evidence", ocr=ocr_text,
                                     locate_notepad_window=lambda _: (0, 0, 600, 350))
            check = dialogs.DialogChecks(runner, None, 0)
            check.wait = lambda label, predicate: predicate(path)
            self.assertFalse(check.document("title-only", "oxide-proof"))
            draw.text((30, 60), "oxide-proof", font=font, fill="black")
            image.save(path)
            self.assertTrue(check.document("loaded", "oxide-proof"))

    def test_desktop_acceptance_calls_dialog_checks_before_exit(self):
        import importlib.util
        from contextlib import ExitStack
        source = Path(__file__).resolve().parents[1] / "windows-notepad-acceptance.py"
        spec = importlib.util.spec_from_file_location("dialog_wiring_test", source)
        runner = importlib.util.module_from_spec(spec)
        with tempfile.TemporaryDirectory(prefix="B3630-wiring-") as tmp, ExitStack() as stack:
            stack.enter_context(patch.dict("os.environ", {"OXIDE_NOTEPAD_ACCEPTANCE_DIR": tmp}))
            stack.enter_context(patch("atexit.register"))
            stack.enter_context(patch.dict(sys.modules, {spec.name: runner}))
            spec.loader.exec_module(runner)
            for name in ("launch_on_desktop", "wait_marker", "ensure_notepad_active",
                         "probe_cadence", "type_token", "drive_menu", "report_cadence", "keys", "qmp"):
                stack.enter_context(patch.object(runner, name))
            stack.enter_context(patch.object(runner.time, "sleep"))
            stack.enter_context(patch.object(runner, "screenshot", return_value=("frame", "digest")))
            stack.enter_context(patch.object(runner, "token_in_notepad_window", return_value=(True, (0, 0, 100, 100))))
            factory = stack.enter_context(patch.object(runner, "DialogChecks"))
            class ReachedDialogs(Exception):
                pass
            factory.return_value.run.side_effect = ReachedDialogs
            reader = SimpleNamespace(text=lambda: "[WINDOWS-NOTEPAD] runtime-exit status=0")
            with self.assertRaises(ReachedDialogs):
                runner.run_desktop_checks(None, reader, "qmp", 10**20)
            factory.assert_called_once_with(runner, "qmp", 10**20, None)
            runner.keys.assert_not_called()

    def test_filename_injection_handles_windows_path_punctuation(self):
        sent = []
        runner = SimpleNamespace(keys_immediate=lambda conn, *names: sent.append(names))
        check = dialogs.DialogChecks(runner, None, 0)
        check.filename("z:\\tmp\\a-1.txt")
        self.assertEqual(sent[:2], [("alt", "n"), ("ctrl", "a")])
        self.assertIn(("shift", "semicolon"), sent)
        self.assertEqual(sent.count(("backslash",)), 2)
        self.assertIn(("dot",), sent)
        self.assertIn(("minus",), sent)

    def test_missing_dialog_fails_at_deadline_and_keeps_last_frame(self):
        runner = SimpleNamespace(screenshot=lambda conn, label: ("last-frame.ppm", "hash"),
                                 die=lambda message: (_ for _ in ()).throw(RuntimeError(message)))
        check = dialogs.DialogChecks(runner, None, 0)
        with self.assertRaisesRegex(RuntimeError, "retained last-frame.ppm"):
            check.wait("about", lambda path: None)


if __name__ == "__main__":
    unittest.main()
