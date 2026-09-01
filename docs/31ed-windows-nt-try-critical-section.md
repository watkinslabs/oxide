# Windows NT native critical-section try-enter

FROZEN 2026-08-31. Dep: 01,02,31ec,52,53. Provides the native RtlTryEnterCriticalSection export required by the installed 64-bit Wine Notepad graph.

The bridge performs the nonblocking owner acquisition and recursive-owner path against the Windows critical-section layout, returning the Windows boolean result.
