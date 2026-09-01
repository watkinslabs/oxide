# Windows NT Unicode-to-multibyte size

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`52`,`53`. Provides: native byte-size calculation for counted UTF-16 strings on the NTDLL locale surface.

## 1

`RtlUnicodeToMultiByteSize` converts the counted UTF-16 source for sizing,
writes the resulting multibyte byte count to a required `DWORD`, and returns
`STATUS_SUCCESS`. The native runtime currently uses UTF-8 as its active
multibyte representation, including surrogate-pair handling and complete
UTF-16-code-unit treatment for an odd source byte count. Invalid checked user
memory returns `STATUS_INVALID_PARAMETER`; Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, focused conversion tests, and the
installed Wine Notepad graph census cover the ABI wiring. The current graph
frontier is `RtlUnicodeToOemN`.
