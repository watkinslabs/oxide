# Windows NT lowercase character classification

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: native `islower` classification for the Windows NTDLL CRT surface.

## 1

`islower` returns the reference `C1_LOWER` mask for ASCII `a`–`z` and zero
for other supported byte values. The native boundary safely returns zero
outside the supported byte domain; Linux dispatch is unchanged.

## 2

The selector and native NTDLL export are appended without renumbering existing
services. Decoder tests, export resolution, scalar classification coverage,
and the installed Wine Notepad graph census cover the ABI wiring. The current
graph frontier is `memcpy`.
