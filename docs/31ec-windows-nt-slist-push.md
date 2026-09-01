# Windows NT native SLIST push

FROZEN 2026-08-31. Dep: 01,02,31eb,52,53. Provides the native RtlInterlockedPushEntrySList export required by the installed 64-bit Wine Notepad graph.

The bridge links a checked, 16-byte-aligned entry into the x86_64 SLIST header, updates depth and sequence, and returns the former head pointer.
