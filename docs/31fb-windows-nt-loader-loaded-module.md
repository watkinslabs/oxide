# Windows NT native loaded-module loader query

FROZEN 2026-08-31. Dep: 01,02,31fa,52,53. Provides `LdrLoadDll` lookup for already mapped 64-bit PE modules.

The native path validates the input `UNICODE_STRING`, searches the canonical PEB loader list case-insensitively, returns the existing module base, and reports `STATUS_DLL_NOT_FOUND` when runtime VFS-backed mapping is required. Dynamic mapping remains a separate loader boundary.
