# Windows NT native SLIST flush

FROZEN 2026-08-31. Dep: 01,02,31ea,52,53. Provides the native RtlInterlockedFlushSList export required by the installed 64-bit Wine Notepad graph.

The x86_64 SLIST ABI is read and cleared as a 16-byte header; the detached, 16-byte-aligned first-entry pointer is returned through checked user-memory operations.
