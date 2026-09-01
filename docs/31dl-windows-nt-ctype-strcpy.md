# Windows NT native strcpy

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `strcpy` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation reads the complete NUL-terminated source string into
kernel memory, copies its terminating NUL, and writes the result to the
destination through the checked user-copy boundary. It returns the original
destination pointer. Null, inaccessible, or unterminated strings return
`STATUS_INVALID_PARAMETER`.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
