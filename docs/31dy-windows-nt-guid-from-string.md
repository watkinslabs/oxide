# Windows NT native GUID parsing

FROZEN 2026-08-31. Dep: `01`,`02`,`31dx`,`52`,`53`. Provides: the native NTDLL `RtlGUIDFromString` export required by the installed 64-bit Wine Notepad graph.

## 1

The implementation validates Wine's fixed `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` UTF-16 form and writes the Windows little-endian 16-byte GUID layout through checked user copies.

## 2

The selector, export resolver, ABI shape, and focused Notepad graph census are covered by tests. The next graph frontier is recorded after the focused census.
