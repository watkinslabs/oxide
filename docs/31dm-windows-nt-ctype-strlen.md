# Windows NT native strlen

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `strlen` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans a NUL-terminated user string and returns the byte
distance to its terminator. A null, inaccessible, or unterminated string
returns zero; an empty valid string therefore has the same numeric result.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
