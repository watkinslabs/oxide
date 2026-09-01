# Windows NT native debug output

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `__wine_dbg_output` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation performs a checked NUL-terminated user read and emits the
result through the existing Linux-owned descriptor write path for descriptor
2. Invalid pointers and unterminated input are rejected without changing the
Linux syscall routes.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Wine’s per-thread partial-line buffer remains the next
debug-runtime fidelity frontier.
