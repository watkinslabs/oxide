# Windows NT native strcat

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `strcat` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans the destination and source as NUL-terminated user
strings, stages the complete result in kernel memory, and writes the result
back through the checked user-copy boundary. It returns the original
destination pointer. Null pointers, unterminated or inaccessible strings, and
an inaccessible destination return `STATUS_INVALID_PARAMETER`.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
