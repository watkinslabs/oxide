"""Real acceptance screenshot caller; QMP supplies hosted PPM bytes only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import screenshot_evidence as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="screenshot-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        spec = importlib.util.spec_from_file_location("screenshot_runner", TOOLS / "windows-notepad-acceptance.py")
        self.runner = importlib.util.module_from_spec(spec)
        with patch("atexit.register"), patch.dict(os.environ, {"OXIDE_NOTEPAD_ACCEPTANCE_DIR": str(self.out)}):
            spec.loader.exec_module(self.runner)
        self.journal = self.out / f"screenshots-{self.runner.RUN}.jsonl"

    def validate_record(self, record):
        schema = json.loads((TOOLS / "screenshot-evidence.schema.json").read_text())
        self.assertEqual(set(record), set(schema["required"]))
        self.assertFalse(schema["additionalProperties"])
        for key, rule in schema["properties"].items():
            if "const" in rule:
                self.assertEqual(record[key], rule["const"])
            if "type" in rule:
                self.assertIs(type(record[key]), {"integer": int, "string": str}[rule["type"]])
            if "pattern" in rule:
                self.assertRegex(record[key], rule["pattern"])

    def test_actual_caller_stamps_completion_before_hash_and_appends_full_evidence(self):
        clock = [0, 0]
        payloads = [b"P6\n2 2\n255\n" + bytes([color]) * 12 for color in (0, 255)]
        expected = []
        original_read = Path.read_bytes

        def command(conn, name, arguments):
            self.assertEqual(name, "screendump")
            path = Path(arguments["filename"])
            payload = payloads[len(expected)]
            path.write_bytes(payload)
            os.utime(path, (1, 1))  # Deliberately unrelated to command completion.
            clock[:] = [100 + len(expected), 1700000000000000000 + len(expected)]
            expected.append((tuple(clock), hashlib.sha256(payload).hexdigest()))
            return {"return": {}}

        def read(path):
            if path.suffix == ".ppm":
                clock[:] = [900, 1900000000000000000]
            return original_read(path)

        with patch.object(self.runner, "qmp", side_effect=command), \
             patch.object(evidence.time, "monotonic_ns", side_effect=lambda: clock[0]), \
             patch.object(evidence.time, "time_ns", side_effect=lambda: clock[1]), \
             patch.object(Path, "read_bytes", read), \
             patch.object(evidence.os, "fsync", wraps=os.fsync) as synced:
            for _ in range(2):
                self.runner.screenshot(None, "response")
            self.assertEqual(synced.call_count, 4, "sync each JSONL record and directory")
        records = [json.loads(line) for line in self.journal.read_text().splitlines()]
        self.assertEqual(len(records), 2)
        for record, (clocks, digest) in zip(records, expected):
            self.validate_record(record)
            self.assertEqual(record["run_id"], self.runner.RUN)
            self.assertEqual(record["label"], "response")
            self.assertEqual(record["path"], str(Path(f"{self.runner.SCREEN}-response.ppm").resolve()))
            self.assertEqual(record["sha256"], digest)
            self.assertEqual(record["command_completed_monotonic_ns"], clocks[0])
            self.assertEqual(record["command_completed_unix_ns"], clocks[1])

    def test_failed_qmp_emits_no_success_record(self):
        with patch.object(self.runner, "qmp", side_effect=SystemExit(1)):
            with self.assertRaises(SystemExit):
                self.runner.screenshot(None, "failed")
        self.assertFalse(self.journal.exists())

    def test_sync_failure_is_not_reported_as_durable(self):
        with patch.object(evidence.os, "fsync", side_effect=OSError("injected sync error")):
            with self.assertRaises(OSError):
                evidence.record_screenshot(self.journal, "run", "frame", self.out / "frame.ppm", "a" * 64, (1, 2))

    def test_truncated_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            evidence.record_screenshot(self.journal, "run", "frame", self.out / "frame.ppm", "a" * 16, (1, 2))
        self.assertFalse(self.journal.exists())


if __name__ == "__main__":
    unittest.main()
