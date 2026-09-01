# Windows NT native tolower

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `tolower` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation applies ASCII uppercase-to-lowercase conversion based on
the low signed-byte view of the input, while returning the original integer for
all other values. This preserves the reference behavior for non-ASCII and
out-of-range integer inputs.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
