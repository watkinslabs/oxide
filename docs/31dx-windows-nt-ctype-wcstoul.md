# Windows NT native wcstoul

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `wcstoul` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation parses a NUL-terminated UTF-16 string with Windows-style
sign, base detection, hexadecimal prefix, digit validation, end-pointer, and
unsigned 32-bit saturation behavior.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. Linux dispatch remains unchanged. The next graph frontier is
recorded in `scratch/known_issues.md` after the focused census.
