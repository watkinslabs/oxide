# Windows NT OEM-to-Unicode conversion

Status: FROZEN
Date: 2026-08-31

`RtlOemStringToUnicodeString` reads the counted `STRING` descriptor, converts
its bytes into a counted `UNICODE_STRING`, always writes a trailing UTF-16 NUL,
and uses the native process heap when `doalloc` is true. The implementation
keeps descriptor and user-buffer copies fault-safe and returns the Windows
buffer-overflow and invalid-parameter statuses for bounded callers.
