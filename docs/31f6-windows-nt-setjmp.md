# Windows NT native x86-64 setjmp boundary

FROZEN 2026-08-31. Dep: 01,02,31f5,52,53. Provides the native `_setjmp` export required by the installed 64-bit Wine Notepad graph.

The bridge captures the live NT task frame and writes Wine's x86-64 integer jump-buffer layout through checked user memory. SIMD continuation remains an architecture-context follow-up.
