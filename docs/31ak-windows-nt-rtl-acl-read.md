# Windows NT RTL ACL read helpers

Status: FROZEN
Frozen: 2026-08-31

## Contract

The native x86-64 NTDLL surface exposes `RtlGetAce` as a read-only ACL
query. It validates the ACL header, checks the requested ACE index, walks
the variable-length ACE records within the declared ACL size, and writes
the selected ACE address through the user-access boundary. Malformed
headers, truncated records, invalid pointers, and out-of-range indices
return `STATUS_INVALID_PARAMETER`.

The helper does not copy or reinterpret the ACE payload and does not create
a second security store. ACL ownership remains with the caller and the
existing NT security adapter.

The native surface also exposes `RtlGetControlSecurityDescriptor`. It reads
the revision and control word from the descriptor, validates revision 1, and
writes both scalar results through the user-access boundary.

`RtlLengthSecurityDescriptor` is also native. It accounts for the fixed
descriptor, referenced SID lengths, and present ACL sizes for both the
self-relative and absolute layouts, returning zero for invalid user data.

`RtlMakeSelfRelativeSD` is native for the same layouts. It reports the
required packed size before writing, copies an existing self-relative
descriptor transactionally, and packs validated absolute SID/ACL references
into a self-relative descriptor through the user-access boundary.

`RtlQueryInformationAcl` is native for `AclRevisionInformation` and
`AclSizeInformation`, reporting the revision, ACE count, bytes in use, and
remaining ACL capacity after validating every ACE record.

`RtlSelfRelativeToAbsoluteSD` is exported for dependency discovery, but its
eleven-argument Windows ABI is not yet representable by the current six-slot
NT entry record; it remains explicitly behavior-incomplete.

## Verification

- Selector decoding covers `RtlGetAce` at selector 81.
- The native NTDLL resolver exposes the export for dependency discovery.
- The Notepad graph harness records the next unresolved NTDLL import after
  the helper is covered.
- Both kernel architecture checks compile the user-memory validation path.
