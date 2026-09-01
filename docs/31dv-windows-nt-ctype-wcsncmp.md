# Windows NT native wcsncmp

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcsncmp` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation performs a bounded comparison of UTF-16 code units and
returns the signed difference at the first mismatch or at the comparison
limit. A zero count returns zero without dereferencing either string.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
