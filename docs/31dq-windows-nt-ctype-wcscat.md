# Windows NT native wcscat

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcscat` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation appends the source's NUL-terminated UTF-16 code units to
the destination, preserving surrogate pairs and returning the destination
pointer. It stages the complete result before copying it to user memory.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
