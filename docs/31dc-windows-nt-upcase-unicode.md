# Windows NT Unicode uppercasing

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`52`,`53`. Provides: native uppercasing for counted UTF-16 strings at the NTDLL boundary.

## 1

`RtlUpcaseUnicodeString` reads a counted UTF-16 source descriptor and writes
the same-length transformed code units to the destination descriptor. The
native path supports allocation through the process-owned native heap and
returns `STATUS_BUFFER_OVERFLOW` for an undersized caller buffer. Checked
user-memory failures return `STATUS_INVALID_PARAMETER`; the current locale
mapping covers the ASCII case range while preserving all other UTF-16 code
units, and Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, shared descriptor coverage, and
the installed Wine Notepad graph census cover the ABI wiring. The current
graph frontier is `RtlUpperChar`.
