# Windows NT native function lookup boundary

FROZEN 2026-08-31. Dep: 01,02,31f0,52,53. Provides the native `RtlLookupFunctionEntry` export required by the installed 64-bit Wine Notepad graph.

The synthetic native NTDLL page has no exception directory, so its lookup returns no function entry and clears the required module-base output. Loaded PE exception-directory registration remains an explicit next implementation frontier.
