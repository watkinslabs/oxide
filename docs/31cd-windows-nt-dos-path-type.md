# Windows NT DOS path classification

Status: FROZEN
Date: 2026-08-31

`RtlDetermineDosPathNameType_U` classifies relative, rooted, UNC, drive,
local-device, and root-local-device DOS paths using bounded UTF-16 reads.
Malformed or inaccessible user pointers return `STATUS_INVALID_PARAMETER` at
the native boundary; Linux pathname lookup is unchanged.
