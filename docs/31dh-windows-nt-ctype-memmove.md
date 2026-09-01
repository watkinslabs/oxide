# Windows NT native memmove

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `memmove` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation stages all source bytes through kernel memory before writing
the destination. This gives the required overlap-safe result while keeping
fault recovery at the user-copy boundary. A zero-length call returns the
destination pointer without dereferencing either pointer.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Invalid nonzero ranges return `STATUS_INVALID_PARAMETER`;
Linux dispatch remains unchanged. The next graph frontier is recorded in
`scratch/known_issues.md` after the focused census.
