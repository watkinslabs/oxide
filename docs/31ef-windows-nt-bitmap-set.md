# Windows NT native bitmap set query

FROZEN 2026-08-31. Dep: 01,02,31ee,52,53. Provides the native `RtlAreBitsSet` export required by the installed 64-bit Wine Notepad graph.

The bridge validates the `RTL_BITMAP` descriptor and requested range, reads LSB-first bits from checked user memory, and returns the Windows boolean result.
