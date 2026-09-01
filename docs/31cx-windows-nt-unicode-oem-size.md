# Windows NT Unicode-to-OEM size

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`52`,`53`. Provides: native size calculation for counted Unicode strings on the OEM conversion path.

## 1

`RtlUnicodeStringToOemSize` reads the x64 `UNICODE_STRING` descriptor and
returns the OEM byte count plus one terminating byte. The count uses the
active reference OEM encoding, UTF-8 in the current native runtime
configuration; valid surrogate pairs count as one four-byte sequence. The
descriptor `MaximumLength` is not consulted because this is a size query.

Length is counted in complete UTF-16 code units. Checked user-memory access
returns zero for an invalid descriptor or inaccessible non-empty buffer, while
an empty string requires one byte for its terminator. Linux dispatch is
unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests and the installed Wine Notepad graph census cover the
ABI wiring; the current graph frontier is `RtlUnicodeStringToOemString`.
