# Windows NT native x86-64 exception-aware setjmp

FROZEN 2026-08-31. Dep: 01,02,31f6,52,53. Provides the native `_setjmpex` export required by the installed 64-bit Wine Notepad graph.

The exception-aware entry uses the same Wine jump-buffer layout as `_setjmp` and records its exception-frame argument in the buffer's frame slot.
