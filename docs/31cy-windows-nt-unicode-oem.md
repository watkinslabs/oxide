# Windows NT Unicode-to-OEM conversion

FROZEN 2026-08-31. Dep:`01`,`02`,`31cx`,`31h`,`31r`,`52`,`53`. Provides: native conversion for counted Unicode strings on the OEM path.

## 1

`RtlUnicodeStringToOemString` writes an x64 `STRING` containing the OEM bytes
and a terminating zero. Allocation mode obtains the destination from the
process-owned native heap and publishes `Length`, `MaximumLength`, and
`Buffer` only after the source conversion and buffer write succeed. Caller
buffer mode returns `STATUS_BUFFER_OVERFLOW` when capacity is insufficient,
copies the representable prefix, and still terminates it; zero capacity does
not dereference a null buffer.

The conversion consumes only the counted UTF-16 source and handles surrogate
pairs using the active UTF-8 OEM configuration. Failed user copies and heap
allocation failures do not leave a published partial descriptor. Linux
personality dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, and the installed Wine Notepad
graph census cover the ABI wiring. The current graph frontier is
`RtlUnicodeToMultiByteSize`.
