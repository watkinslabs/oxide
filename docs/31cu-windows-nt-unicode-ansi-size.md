# Windows NT Unicode-to-ANSI size

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`52`,`53`. Provides: native size calculation for Wine's Unicode descriptor conversion path.

## 1

`RtlUnicodeStringToAnsiSize` reads the x64 `UNICODE_STRING` descriptor (`Length`,
`MaximumLength`, padding, and 64-bit `Buffer`) and returns the number of ANSI
bytes required for the counted UTF-16 payload plus one terminating byte. The
maximum-length field does not limit the counted payload; `Length` is the source
contract, and an odd length is rejected because the source is UTF-16.

The native adapter uses checked user-memory access. A null descriptor, null
buffer for a non-empty string, overflowed address, or inaccessible source
returns zero without publishing state. An empty descriptor returns one for the
terminator. UTF-16 surrogate pairs count as one four-byte UTF-8 sequence;
other scalar values use their UTF-8 width.

## 2

The selector is appended to the NT service namespace, preserving all existing
selectors. The native NTDLL page exports the function and the Notepad graph
census verifies that it resolves from the kernel-provided page. Decoder tests
verify the service identifier and argument preservation. The current graph
frontier is `RtlUnicodeStringToAnsiString`.
