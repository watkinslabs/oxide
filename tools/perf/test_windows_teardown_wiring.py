"""Structural Rust boundary contracts, NOT runtime execution or lock-safety proof.

Balanced function/block bodies and ordered statements pin the production route.
Mutation controls operate on source copies in memory; no live source is changed.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "crates/kernel/syscalls/src"
HOOK = "crate::nt_window::cleanup_thread_at_exit(task);"


def code(source):
    """Mask comments/literals before matching; preserve braces in code only."""
    pattern = r'//[^\n]*|/\*|r(\#*)"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\''
    out, pos = [], 0
    while match := re.search(pattern, source[pos:]):
        start, end = pos + match.start(), pos + match.end()
        out.append(source[pos:start])
        token = source[start:end]
        if token == "/*":
            depth = 1
            while depth:
                nested = re.search(r'/\*|\*/', source[end:])
                assert nested, "unterminated block comment"
                depth += 1 if nested.group() == "/*" else -1
                end += nested.end()
        elif token.startswith('r'):
            terminator = '"' + match.group(1)
            close = source.find(terminator, end)
            assert close >= 0, "unterminated raw string"
            end = close + len(terminator)
        out.append(" ")
        pos = end
    out.append(source[pos:])
    return re.sub(r'\s+', '', ''.join(out))


def block(source, marker):
    assert source.count(marker + '{') == 1 or source.count(marker) == 1, f"expected one {marker}"
    start = source.index('{', source.index(marker) + len(marker))
    depth = 1
    for end in range(start + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if depth == 0:
            return source[start + 1:end], end + 1
    raise AssertionError(f"unclosed {marker}")


def ordered(body, *statements):
    previous = -1
    for statement in statements:
        statement = code(statement)
        assert body.count(statement) == 1, f"expected one statement: {statement}"
        current = body.index(statement)
        assert current > previous, f"out-of-order statement: {statement}"
        previous = current


def check_exit(source):
    body, _ = block(code(source), 'fndo_exit(status:i32)')
    task_body, _ = block(body, 'if!raw.is_null()')
    ordered(task_body, 'let task: &sched::Task = unsafe { &*raw };', HOOK,
            'crate::nt_native_thread::cleanup_at_exit(task);',
            'task.replace_mm(None);', 'sched::live::mark_done(task);')


def check_cleanup(source):
    body, _ = block(code(source), 'fncleanup_thread_at_exit(task:&sched::Task)')
    revoked, end = block(body, 'letremoved=')
    ordered(revoked, 'let mut entries = GUI.lock();',
            'let removed = entry.state.exit_thread(task.tid as u64);',
            'crate::nt_retrieval_policy::cancel_thread(&mut entry.retrievals, task.tid as u64);')
    assert revoked.endswith('removed'), 'revoked HWNDs must leave GUI scope'
    assert 'cancel_position_' not in revoked and 'bridge::' not in revoked
    tail = body[end:]
    ordered(tail, 'position::cancel_position_thread(group, task.tid as u64);', 'for window in removed')
    windows, _ = block(tail, 'forwindowinremoved')
    ordered(windows, 'position::cancel_position_window(group, window.raw() as u64);',
            'let _ = bridge::publish_destroy_current(window.raw() as u64);',
            'crate::nt_gdi::destroy_window_dc_for_current(window.raw());')


class TeardownStructuralTests(unittest.TestCase):
    def test_production_exit_body_order(self):
        check_exit((BASE / '060_exit.rs').read_text())

    def test_production_cleanup_body_order(self):
        check_cleanup((BASE / 'nt_window/teardown.rs').read_text())

    def test_production_module_route(self):
        source = (BASE / 'nt_window.rs').read_text()
        self.assertRegex(source, r'#\[path\s*=\s*"nt_window/teardown.rs"\]\s*mod teardown;')
        self.assertIn('pub(crate)useteardown::cleanup_thread_at_exit;', code(source))

    def test_removed_hook_red_restored_green(self):
        source = (BASE / '060_exit.rs').read_text()
        self.assertEqual(source.count(HOOK), 1)
        broken = source.replace(HOOK, '')
        with self.assertRaisesRegex(AssertionError, 'expected one statement'):
            check_exit(broken)
        check_exit(source)

    def test_comment_or_string_cannot_replace_hook(self):
        source = (BASE / '060_exit.rs').read_text()
        for fake in ['/* ' + HOOK + ' */', 'let fake = r#"' + HOOK + '"#;']:
            with self.assertRaises(AssertionError):
                check_exit(source.replace(HOOK, fake))

    def test_hook_after_mm_detach_is_red(self):
        source = (BASE / '060_exit.rs').read_text().replace(HOOK, '')
        with self.assertRaisesRegex(AssertionError, 'out-of-order'):
            check_exit(source.replace('task.replace_mm(None);', 'task.replace_mm(None);' + HOOK))

    def test_missing_canonical_revocation_is_red(self):
        source = (BASE / 'nt_window/teardown.rs').read_text()
        with self.assertRaises(AssertionError):
            check_cleanup(source.replace('entry.state.exit_thread(task.tid as u64)', 'Vec::new()'))


if __name__ == '__main__':
    unittest.main()
