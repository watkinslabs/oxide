"""Typing must not be paced by the harness that measures it.

Measured in one acceptance run, same guest, same control, three deliveries
of the same eight characters: 76 ms per character over `send-key` at QEMU's
default 100 ms hold, 74 ms over `send-key` at a 5 ms hold, and 11 ms over
`input-send-event`. The hold is not what paces it -- the queue behind
`send-key` is -- so text leaves that queue entirely and only chords, which
are not on the measured path, still use it.

Positive control: send the token's characters through `send-key` again and
`test_typed_characters_do_not_go_through_the_paced_queue` fails.
"""
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
    def test_typed_characters_do_not_go_through_the_paced_queue(self):
        """Measured in the tgt-B3567 acceptance run: 74-76 ms per character
        over `send-key` at either hold, 11 ms over `input-send-event`. The
        hold is not what paces it, so shortening the hold is not the fix --
        the characters have to leave the queue entirely."""
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.type_token(Mock())
        commands = [command for command, _ in sent]
        self.assertEqual(commands.count("input-send-event"), len(runner.TOKEN))
        # Only the select-all chord ahead of the text stays on send-key.
        self.assertEqual(commands.count("send-key"), 1)

    def test_chords_carry_an_explicit_short_hold(self):
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.keys(Mock(), "ctrl", "a")
        self.assertEqual(sent[0][1].get("hold-time"), runner.KEY_HOLD_MS)
        self.assertLess(runner.KEY_HOLD_MS, 100)

    def test_the_immediate_path_presses_and_releases_in_one_transaction(self):
        sent, capture = record()
        with patch.object(runner, "qmp", capture):
            runner.keys_immediate(Mock(), "ctrl", "a")
        self.assertEqual(len(sent), 1)
        command, arguments = sent[0]
        self.assertEqual(command, "input-send-event")
        self.assertEqual([(event["data"]["down"], event["data"]["key"]["data"]) for event in arguments["events"]],
                         [(True, "ctrl"), (True, "a"), (False, "a"), (False, "ctrl")])

    def test_the_probe_types_every_delivery_shape_and_pauses_between_them(self):
        sent, capture = record()
        slept = []
        with patch.object(runner, "qmp", capture), patch.object(runner.time, "sleep", slept.append):
            runner.probe_cadence(Mock())
        typed = [arguments for command, arguments in sent if command == "send-key"]
        # One phase is deliberately typed at QEMU's default hold: it is the
        # control the other phases are compared against.
        self.assertIn(None, [arguments.get("hold-time") for arguments in typed])
        self.assertIn(runner.KEY_HOLD_MS, [arguments.get("hold-time") for arguments in typed])
        self.assertEqual(len([1 for command, _ in sent if command == "input-send-event"]), 8)
        self.assertEqual(slept, [runner.notepad_cadence.PHASE_PAUSE_SECONDS] * len(runner.CADENCE_PHASES))

    def test_the_cadence_report_names_every_phase_and_the_token(self):
        reader = Mock()
        reader.text.return_value = ""
        written = {}
        with patch.object(runner, "CADENCE_MD", Mock(write_text=lambda text: written.setdefault("text", text))):
            runner.report_cadence(reader)
        for label, _, _ in runner.CADENCE_PHASES:
            self.assertIn(label, written["text"])
        self.assertIn("token", written["text"])


if __name__ == "__main__":
    unittest.main()
