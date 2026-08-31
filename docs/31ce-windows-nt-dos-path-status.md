# Windows NT DOS path conversion status

Status: FROZEN
Date: 2026-08-31

`RtlDosPathNameToNtPathName_U_WithStatus` shares the native DOS-to-NT
conversion owner with the boolean form and returns an NT status result. A
successful conversion returns `STATUS_SUCCESS`; malformed, unsupported, or
unreadable input returns a failure status without changing Linux pathname
lookup.
