# Windows NT native memset

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `memset` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation fills a kernel staging buffer with the low byte of the
requested integer value, then copies it to user memory. A zero-length call
returns the destination pointer without dereferencing it; invalid nonzero
ranges return `STATUS_INVALID_PARAMETER`.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
