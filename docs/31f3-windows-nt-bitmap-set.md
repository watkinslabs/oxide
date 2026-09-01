# Windows NT native bitmap mutation

FROZEN 2026-08-31. Dep: 01,02,31f2,52,53. Provides the native `RtlSetBits` export required by the installed 64-bit Wine Notepad graph.

The bridge validates the bitmap descriptor and range, then sets the requested LSB-first bits through checked user-memory reads and writes. Invalid ranges preserve the bitmap, matching the reference contract.
