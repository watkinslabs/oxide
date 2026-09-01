# Windows NT native x86-64 longjmp

FROZEN 2026-08-31. Dep: 01,02,31f7,52,53. Provides the native `longjmp` export required by the installed 64-bit Wine Notepad graph.

The bridge restores Wine's saved nonvolatile integer registers, stack, instruction pointer, and normalized return value through the live x86-64 NT task frame.
