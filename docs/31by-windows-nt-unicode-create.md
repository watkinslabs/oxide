# Windows NT Unicode string creation

Status: FROZEN
Date: 2026-08-31

`RtlCreateUnicodeString` copies a null-terminated UTF-16 string into a
process-heap allocation and publishes a counted `UNICODE_STRING` descriptor.
The allocation includes the terminating code unit, while `Length` excludes
it and `MaximumLength` includes it. Failed user reads, allocation, or output
writes release the native allocation and return the Boolean failure result.

The implementation uses the same VMM-backed heap owner as the other native
RTL string services. Linux string and allocation paths are unchanged.
