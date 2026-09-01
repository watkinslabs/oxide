# Windows NT native debug string duplication

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `__wine_dbg_strdup` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation gives each NT thread a Wine-shaped 0x800-byte debug area,
copies checked NUL-terminated strings into its 0x3fc-byte arena, wraps at the
arena boundary, and returns the resulting user pointer.

## 2

The selector, decoder, TEB allocation, export resolver, and graph census are
covered by tests. The next graph frontier is recorded after the focused census.
