# Windows NT ASCII character classification

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: native `isalpha` classification for the Windows NTDLL CRT surface.

## 1

`isalpha` returns the reference classification mask for one signed `int`:
`C1_UPPER` for `A`–`Z`, `C1_LOWER` for `a`–`z`, and zero for other values.
The native boundary safely returns zero outside the supported byte domain;
Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, scalar classification coverage,
and the installed Wine Notepad graph census cover the ABI wiring. The current
graph frontier is `islower`.
