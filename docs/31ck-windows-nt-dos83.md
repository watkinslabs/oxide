# Windows NT DOS 8.3 names

Status: FROZEN
Date: 2026-08-31

`RtlIsNameLegalDOS8Dot3` validates counted UTF-16 names using the DOS 8.3
length, separator, dot, and space rules and emits uppercase ASCII-compatible
OEM bytes when requested. Unsupported non-ASCII conversion and invalid output
buffers fail without changing Linux pathname policy.
