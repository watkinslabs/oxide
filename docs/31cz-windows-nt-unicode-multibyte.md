# Windows NT Unicode-to-multibyte conversion

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`31r`,`52`,`53`. Provides: native counted UTF-16 to multibyte conversion for the NTDLL locale surface.

## 1

`RtlUnicodeToMultiByteN` converts at most the requested destination length
from a counted UTF-16 source, optionally returning the number of bytes
written. The native runtime currently uses UTF-8 as its active multibyte
representation, including surrogate-pair handling and the reference's
complete-code-unit treatment for an odd source byte count. Truncation is a
successful conversion; invalid descriptors and failed checked user copies
return `STATUS_INVALID_PARAMETER`.

The result-length pointer is optional. A zero destination length performs the
size-limited conversion without dereferencing a null destination, while a
nonzero write requires a valid user destination. Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, focused conversion tests, and the
installed Wine Notepad graph census cover the ABI wiring. The current graph
frontier is `RtlUnicodeToOemN`.
