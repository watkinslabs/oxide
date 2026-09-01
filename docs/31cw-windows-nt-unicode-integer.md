# Windows NT Unicode string integer parsing

FROZEN 2026-08-31. Dep:`01`,`02`,`31ae`,`31h`,`52`,`53`. Provides: native parsing of counted UTF-16 integers for the Windows RTL boundary.

## 1

`RtlUnicodeStringToInteger` validates the requested base before checking the
output pointer. Base zero selects decimal unless the post-sign input begins
with lowercase `0b`, `0o`, or `0x`; explicit bases do not consume prefixes.
Leading UTF-16 values at or below space are skipped, followed by one optional
sign. Parsing stops at the first invalid digit and accumulates with 32-bit
wrapping. Invalid base returns `STATUS_INVALID_PARAMETER`; a null output
returns `STATUS_ACCESS_VIOLATION`.

The descriptor and counted buffer are read through checked user-memory access.
Odd `Length` values consume the complete UTF-16 code-unit count obtained by
integer division, and an empty string produces zero. Linux personality dispatch
never enters this service.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests and the installed Wine Notepad graph census cover the
ABI wiring; the current graph frontier is `RtlUnicodeStringToOemSize`.
