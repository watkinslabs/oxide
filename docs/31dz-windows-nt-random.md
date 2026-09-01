# Windows NT native random generation

FROZEN 2026-08-31. Dep: `01`,`02`,`31dy`,`52`,`53`. Provides the native NTDLL `RtlRandom` export required by the installed 64-bit Wine Notepad graph.

The implementation mirrors Wine's two-step linear-congruential update and 128-entry saved-value table, with checked user access to the caller's seed.
