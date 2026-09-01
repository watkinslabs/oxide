# Windows NT native memcpy

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `memcpy` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation stages the source bytes through kernel memory before writing
the destination. This preserves Wine's documented memmove-like overlap behavior
and prevents a faulting destination write from exposing a partially copied
source range to the native adapter. A zero-length call returns the destination
pointer without dereferencing either pointer.

## 2

The service selector, decoder, export resolver, and graph census are covered by
tests. Invalid nonzero ranges return `STATUS_INVALID_PARAMETER`; Linux dispatch
is unchanged. The next measured Notepad graph frontier is recorded in
`scratch/known_issues.md` after the focused census; the current frontier is
`memmove`.
