# Windows NT native wcscmp

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcscmp` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation compares NUL-terminated UTF-16 strings one code unit at a
time and returns the signed difference of the first differing units, matching
the reference behavior without interpreting surrogate pairs as scalar values.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
