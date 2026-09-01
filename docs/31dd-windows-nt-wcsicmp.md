# Windows NT wide-character case-insensitive comparison

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: native `_wcsicmp` comparison for the Windows NTDLL CRT surface.

## 1

`_wcsicmp` walks two null-terminated UTF-16 strings, folds only ASCII
uppercase letters to lowercase, and returns the signed difference at the
first folded mismatch or terminating null. Checked user reads reject null or
inaccessible pointers with `STATUS_INVALID_PARAMETER`; non-ASCII code units
remain unchanged, matching the reference behavior. Linux dispatch is
unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, checked-read coverage, and the
installed Wine Notepad graph census cover the ABI wiring. The current graph
frontier is `isalpha`.
