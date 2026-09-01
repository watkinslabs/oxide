# Windows NT native wcscpy

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcscpy` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation copies a NUL-terminated UTF-16 string, including its
terminator, as code units and returns the destination pointer. The complete
result is staged before copying it to user memory.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
