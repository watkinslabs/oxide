# Windows NT native bitmap initialization

FROZEN 2026-08-31. Dep: 01,02,31ef,52,53. Provides the native `RtlInitializeBitMap` export required by the installed 64-bit Wine Notepad graph.

The bridge writes the 16-byte `RTL_BITMAP` descriptor with its bit count and user buffer pointer through checked user memory, returning success or invalid-parameter status on an invalid destination.
