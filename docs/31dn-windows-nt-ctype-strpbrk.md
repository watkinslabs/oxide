# Windows NT native strpbrk

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `strpbrk` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation scans the first NUL-terminated user string and searches
the second NUL-terminated user string for each byte. It returns the address of
the first matching byte in the first string, or zero when no match exists or a
string is invalid.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
