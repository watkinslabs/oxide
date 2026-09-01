# Windows NT PE image helper boundary

FROZEN 2026-09-01. Dep: 01,02,31ff,52,53. Exposes native PE image helpers
used by Wine's loader and unwind/resource paths.

`RtlImageDirectoryEntryToData` validates a PE32+ header, reports a bounded
directory size, returns mapped-image addresses, and translates raw-file
directories through section headers. `RtlImageRvaToVa` performs the section
table translation and optionally returns the selected section-header address.
Malformed headers, absent directories, out-of-range RVAs, and failed user
writes return a null pointer. PE32 remains outside this x86-64-only runtime
contract.

The user-procedure table exports and UTF-8 multibyte/UTF-16 conversion pair
are also exposed for the current Wine loader graph. Per-process user-procedure
table storage and API-set namespace state remain open runtime work.
