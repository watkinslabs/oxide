"""Complete input chords must precede text on the immediate QMP event path."""
import importlib.util
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SPEC = importlib.util.spec_from_file_location(
    "notepad_acceptance", Path(__file__).resolve().parents[1] / "windows-notepad-acceptance.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def record():
    sent = []
    return sent, lambda conn, command, arguments=None: sent.append((command, arguments))


class TypingRateTests(unittest.TestCase):
    def test_token_chord_and_text_leave_no_delayed_modifier(self):
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.type_token(Mock())
        self.assertEqual(len(sent), len(runner.TOKEN) + 1)
        held = set()
        typed = []
        for command, arguments in sent:
            self.assertEqual(command, "input-send-event", "delayed key releases must not race following text")
            for event in arguments["events"]:
                data = event["data"]
                key = data["key"]["data"]
                if data["down"]:
                    if key == "a" and "ctrl" in held:
                        typed.clear()
                    elif key != "ctrl":
                        self.assertNotIn("ctrl", held, "text would invoke a shortcut")
                        typed.append("-" if key == "minus" else key)
                    held.add(key)
                else:
                    self.assertIn(key, held)
                    held.remove(key)
            self.assertFalse(held, "each completed chord must have released every key")
        self.assertEqual("".join(typed), runner.TOKEN)

    def test_chords_complete_in_one_transaction(self):
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.keys(Mock(), "ctrl", "a")
        self.assertEqual(sent, [("input-send-event", {"events": [
            {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": name}}}
            for down, name in [(True, "ctrl"), (True, "a"), (False, "a"), (False, "ctrl")]
        ]})])

    def test_the_immediate_path_presses_and_releases_in_one_transaction(self):
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.keys_immediate(Mock(), "ctrl", "a")
        self.assertEqual(len(sent), 1)
        command, arguments = sent[0]
        self.assertEqual(command, "input-send-event")
        self.assertEqual([(event["data"]["down"], event["data"]["key"]["data"]) for event in arguments["events"]],
                         [(True, "ctrl"), (True, "a"), (False, "a"), (False, "ctrl")])

    def test_the_cadence_report_names_the_actual_token_input(self):
        reader = Mock()
        reader.text.return_value = ""
        written = {}
        with patch.object(runner, "CADENCE_MD", Mock(write_text=lambda text: written.setdefault("text", text))):
            runner.report_cadence(reader)
        self.assertIn("token", written["text"])


if __name__ == "__main__":
    unittest.main()
