# Windows NT native wcsrchr

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcsrchr` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans a NUL-terminated UTF-16 string, retaining the last
matching code-unit address and including the terminator when the requested
character is NUL.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
