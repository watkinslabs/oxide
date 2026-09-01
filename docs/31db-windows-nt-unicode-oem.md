# Windows NT Unicode-to-OEM conversion

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`31r`,`52`,`53`. Provides: native counted UTF-16 to OEM conversion for the NTDLL locale surface.

## 1

`RtlUnicodeToOemN` converts at most the requested destination length from a
counted UTF-16 source and optionally returns the number of bytes written. The
native runtime currently uses UTF-8 as its active OEM representation,
including surrogate-pair handling and complete-code-unit treatment for an odd
source byte count. Truncation is a successful conversion. Invalid checked
user memory returns `STATUS_INVALID_PARAMETER`; Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, shared conversion coverage, and
the installed Wine Notepad graph census cover the ABI wiring. The current
graph frontier is `RtlUpcaseUnicodeString`.
