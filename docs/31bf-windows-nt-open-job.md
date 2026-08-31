# Windows NT Open Job Object

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtOpenJobObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` for
opening a named job object. Oxide exposes the 64-bit NTDLL export as selector
110, while named NT-object namespaces and object-attribute decoding remain
unimplemented.

The service returns an explicit unsupported NT status and never treats a
Linux process group, file descriptor, or pathname as a job object.
