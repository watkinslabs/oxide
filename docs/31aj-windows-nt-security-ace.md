# Windows NT security ACE helpers

Status: FROZEN
Frozen: 2026-08-31

## Contract

The NT personality exposes the x86-64 NTDLL helpers `RtlAddAce`,
`RtlAddAccessAllowedAce`,
`RtlAddAccessAllowedAceEx`, `RtlAddAccessDeniedAce`, and
`RtlAddAccessDeniedAceEx`. The access helpers validate a user ACL and SID, locate the
first free ACE slot, append one variable-length ACE, advance `AceCount`, and
preserve the ACL revision. `RtlAddAce` appends a caller-supplied sequence of
ACE records. The non-Ex forms use zero ACE flags. Invalid user
memory, malformed ACLs, invalid SIDs, revision mismatches, and insufficient
ACL capacity return the corresponding NT status without entering the Linux
syscall namespace.

Audit ACE names are present in the native export table and selector contract.
Their Ex form has seven Windows arguments, while the current native entry
record carries six; the audit-flag bridge remains open and must not be treated
as behavior-complete.

The implementation is owned by the NT RTL adapter. It writes only through
the user-access boundary and does not create a second Linux security database.
`NtSetSecurityObject` remains a separate object-security persistence surface;
its selector and ABI are defined, but it is not reported complete until
native object security state is connected to the canonical object owner.

## Verification

- Selector decoding covers the five implemented helpers and preserves the six-register
  x86-64 entry shape.
- The native NTDLL resolver exposes the implemented helpers and the audit-ACE
  names for dependency discovery.
- ACL/SID validation and ACE construction are compiled in both kernel target
  configurations; the Notepad graph harness records the next missing NTDLL
  helper after the covered surface.
- Linux syscall decoding remains unable to consume NT selectors.
