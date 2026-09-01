# Windows NT native wcslen

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcslen` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans a NUL-terminated UTF-16 string and returns its length
in UTF-16 code units, matching the native ABI's `size_t` result.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
