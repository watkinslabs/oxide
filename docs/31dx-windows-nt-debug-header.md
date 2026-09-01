# Windows NT native debug header

FROZEN 2026-08-31. Dep: `01`,`02`,`31h`,`52`,`53`. Provides: the native NTDLL `__wine_dbg_header` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation validates the debug class and channel pointer, applies the
Wine default error/fixme flags for a lazily initialized channel, and returns
the Wine disabled sentinel or an accepted header result.

## 2

The selector, decoder, native dispatch, export resolver, and graph census are
covered by tests. The per-thread output buffer and native emission path remain
the next measured debug frontier.
