# Windows NT Unicode-to-ANSI conversion

FROZEN 2026-08-31. Dep:`01`,`02`,`31ag`,`31h`,`31r`,`52`,`53`. Provides: native conversion for counted Unicode strings used by the Wine loader and startup path.

## 1

`RtlUnicodeStringToAnsiString` reads a 16-byte x64 `UNICODE_STRING` and writes
the converted bytes plus a terminator into an x64 `STRING`. With allocation
requested, the destination buffer comes from the process-owned native heap;
otherwise the caller's buffer and `MaximumLength` control the copy. A short
caller buffer receives the representable prefix, is terminated, and returns
`STATUS_BUFFER_OVERFLOW`. A zero-capacity caller buffer returns that status
without dereferencing a null buffer.

The conversion consumes counted UTF-16, handles valid surrogate pairs as one
Unicode scalar, and does not read beyond `Length`. Descriptor publication occurs
only after source reads and destination writes succeed. Failed user copies and
allocation failures leave no partially published allocation.

## 2

The selector and native NTDLL export are appended, preserving existing service
numbers. Decoder tests and the installed Wine Notepad graph census cover the
ABI wiring; the current graph frontier is `RtlUnicodeStringToInteger`.
