# Windows NT ANSI-to-Unicode conversion

Status: FROZEN
Date: 2026-08-31

`RtlAnsiStringToUnicodeString` is implemented at the native NT boundary for
the 64-bit Windows personality. It validates the counted `ANSI_STRING`, emits
a counted UTF-16 `UNICODE_STRING` including its terminator, supports caller
provided buffers and process-heap allocation, and returns the Windows buffer
overflow status when a non-allocating destination is too small.

The current bridge preserves each input byte as a Unicode code unit. This is
the deliberate narrow contract needed by the initial Notepad graph; full
locale/code-page conversion remains a separately testable extension. Invalid
user pointers and failed allocations do not publish a partially initialized
descriptor. Linux personality paths are unchanged.
