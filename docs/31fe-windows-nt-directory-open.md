# Windows NT directory-object open boundary

FROZEN 2026-09-01. Dep: 01,02,31fd,52,53. Exposes validated `NtOpenDirectoryObject` handling.

The native object namespace has no published directory-name registry yet, so valid opens return the canonical missing-object status after zeroing the output handle. Directory creation, named lookup, access checks, and directory enumeration remain required.
