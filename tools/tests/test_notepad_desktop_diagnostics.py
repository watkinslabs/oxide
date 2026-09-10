"""Execute the capture and prove desktop launch actually wires its trigger."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import notepad_desktop_diagnostics as diagnostics


class DesktopCaptureTests(unittest.TestCase):
    def test_capture_retains_credentials_stacks_and_read_failures(self):
        with tempfile.TemporaryDirectory(prefix="notepad capture ") as tmp:
            root = Path(tmp)
            (root / 'self').mkdir()
            (root / 'self/status').write_text('Uid:\t0\nCapEff:\t0000000000200000\n')
            task = root / '387/task/388'
            task.mkdir(parents=True)
            (root / '387/comm').write_text('gnome-shell\n')
            (root / '387/status').write_text('Name:\tgnome-shell\n')
            (root / '387/maps').write_text('process-mappings\n')
            (task / 'comm').write_text('gnome-worker\n')
            (task / 'syscall').write_text('202 0x1234 0x80 0x2\n')
            (task / 'wchan').write_text('futex_wait\n')
            (task / 'stack').write_text('[<0>] 0xffff00001234\n')
            first = subprocess.run(['sh'], input=diagnostics.command(root), capture_output=True, timeout=15)
            text = first.stdout.decode()
            self.assertIn('CapEff:\t0000000000200000', text)
            self.assertLess(text.index('READER-CREDENTIALS'), text.index('PROCESS=387'))
            self.assertIn('202 0x1234 0x80 0x2', text)
            self.assertIn('[<0>] 0xffff00001234', text)
            self.assertIn('[NOTEPAD-DESKTOP-DIAGNOSTICS] complete', text)
            (task / 'stack').unlink()
            second = subprocess.run(['sh'], input=diagnostics.command(root), capture_output=True, timeout=15)
            self.assertIn('READ-STATUS=1', second.stdout.decode())
            self.assertIn('No such file', second.stdout.decode())

    def test_render_wait_polls_capture_before_timeout(self):
        spec = importlib.util.spec_from_file_location('notepad_capture_wait', TOOLS / 'windows-notepad-acceptance.py')
        acceptance = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acceptance)
        now = [0.0]
        uart = Mock()
        capture = diagnostics.DesktopDiagnostics(uart, lambda: now[0])
        def sleep(seconds):
            now[0] += seconds
        def screen(conn, command, arguments):
            Path(arguments['filename']).write_bytes(b'P6\n1 1\n255\n' + b'x' * 32)
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(acceptance, 'SCREEN', Path(tmp) / 'screen'), \
             patch.object(acceptance, 'qmp', screen), \
             patch.object(acceptance.time, 'monotonic', lambda: now[0]), \
             patch.object(acceptance.time, 'sleep', sleep), \
             patch.object(acceptance.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='')):
            with self.assertRaises(SystemExit):
                acceptance.wait_for_rendered_desktop(Mock(), 35, capture)
        uart.sendall.assert_called_once_with(diagnostics.command())

    def test_launch_connects_delayed_once_only_capture_to_desktop_wait(self):
        spec = importlib.util.spec_from_file_location('notepad_capture_acceptance', TOOLS / 'windows-notepad-acceptance.py')
        acceptance = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acceptance)
        uart = Mock()
        now = [100.0]
        captured = []
        def frame_wait(conn, deadline, capture=None):
            self.assertIsNotNone(capture, 'desktop wait must receive the live capture owner')
            capture.poll()
            uart.sendall.assert_not_called()
            now[0] += diagnostics.CAPTURE_AFTER_SECONDS
            capture.poll()
            capture.poll()
            self.assertEqual(uart.sendall.call_count, 1)
            captured.append(uart.sendall.call_args.args[0])
        with patch.object(acceptance, 'wait_marker'), patch.object(acceptance, 'leave_overview'), \
             patch.object(acceptance, 'screenshot'), patch.object(acceptance, 'wait_for_rendered_desktop', frame_wait), \
             patch.object(acceptance, 'DesktopDiagnostics', lambda uart: diagnostics.DesktopDiagnostics(uart, lambda: now[0])):
            acceptance.launch_on_desktop(uart, Mock(), Mock(), 200)
        self.assertEqual(captured, [diagnostics.command()])
        self.assertEqual(uart.sendall.call_args.args[0], acceptance.DESKTOP_LAUNCH)


if __name__ == '__main__':
    unittest.main()
