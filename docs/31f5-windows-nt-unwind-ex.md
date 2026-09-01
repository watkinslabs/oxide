# Windows NT extended unwind boundary

FROZEN 2026-08-31. Dep: 01,02,31f4,52,53. Provides the native `RtlUnwindEx` export required by the installed 64-bit Wine Notepad graph.

The boundary accepts the extended ABI and uses the native x86-64 task-frame transfer shared with `RtlUnwind`; loaded-image handler walking remains coupled to the registered PE exception tables.
