# Windows NT native debug channel flags

FROZEN 2026-08-31. Dep: 01,02,31f8,52,53. Provides the native `__wine_dbg_get_channel_flags` export required by the installed 64-bit Wine Notepad graph.

The ABI reads the Wine debug-channel flags byte, resolves lazy initialization to Wine's documented default FIXME/ERR mask, and writes that resolved mask back to user memory. Per-process `WINEDEBUG` option tables remain a later compatibility frontier.
