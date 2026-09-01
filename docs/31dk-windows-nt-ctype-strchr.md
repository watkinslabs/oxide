# Windows NT native strchr

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `strchr` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans a NUL-terminated user string and returns the
original string address plus the first matching byte offset. The terminating
NUL is searchable. A null, inaccessible, or unterminated string returns zero.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
