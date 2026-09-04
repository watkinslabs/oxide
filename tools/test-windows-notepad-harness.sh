#!/usr/bin/env bash
# Static positive-control for the Notepad acceptance harness.
# A PE commit only installs the first user frame; it is not application
# readiness. Keep smoke admission tied to the user-entry event.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
makefile="$root/Makefile"
exec_source="$root/crates/kernel/syscalls/src/pe_exec.rs"
wine_window_source="$root/crates/kernel/syscalls/src/nt_wine_window.rs"
raw_class_source="$root/crates/kernel/syscalls/src/nt_wine_window/raw_class.rs"

grep -Fq "SMOKE_MARKER='[WINDOWS-PE-START] entry='" "$makefile"
grep -Fq "SMOKE_ALIVE_MARKER='[WINDOWS-PE-START] entry='" "$makefile"
if grep -Fq "SMOKE_MARKER='[WINDOWS-PE-COMMIT] success'" "$makefile"; then
    echo "windows-notepad-harness: commit marker must not admit readiness" >&2
    exit 1
fi

start_line="$(grep -nF '[WINDOWS-PE-START] entry=' "$exec_source" | cut -d: -f1 | head -n1)"
commit_line="$(grep -nF '[WINDOWS-PE-COMMIT] success' "$exec_source" | cut -d: -f1 | head -n1)"
test -n "$start_line" -a -n "$commit_line"
test "$start_line" -lt "$commit_line"
grep -Fq "if ordinal == WINE_REGISTER_CLASS_EX { return Some(raw_class::register_class(args)); }" "$wine_window_source"
grep -Fq "if ordinal == WINE_CREATE_WINDOW_EX { return Some(raw_class::create_window(args)); }" "$wine_window_source"
grep -Fq "pub(super) fn register_class(args: SyscallArgs)" "$raw_class_source"
grep -Fq "pub(super) fn create_window(args: SyscallArgs)" "$raw_class_source"
echo "windows-notepad-harness: PASS (entry marker precedes commit marker and is the smoke admission marker)"
