# Windows NT native wcschr

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcschr` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans a NUL-terminated UTF-16 string by code unit and
returns the address of the first matching unit, including the terminator when
the requested character is NUL. It returns zero when no match is found.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
