# Windows native NT security query

FROZEN 2026-08-31. Dep:`01`,`02`,`31f`,`31h`,`31ad`,`52`,`53`. Provides: a bounded security-descriptor boundary for the first Wine runtime graph.

## Contract

- `NtQuerySecurityObject` is append-only NT service `64`; existing selectors remain unchanged.
- The call requires an NT-personality handle with `READ_CONTROL`.
- `OWNER_SECURITY_INFORMATION`, `GROUP_SECURITY_INFORMATION`, and `DACL_SECURITY_INFORMATION` are supported. SACL and label queries return `STATUS_ACCESS_DENIED` until an audit/label owner exists.
- Results are valid x64 self-relative `SECURITY_DESCRIPTOR` data. Linux effective UID/GID provide deterministic owner/group SIDs, and the baseline DACL grants the compatibility runtime full access.
- A null or short output buffer publishes the required length and returns `STATUS_BUFFER_TOO_SMALL`; usercopy faults return `STATUS_INVALID_PARAMETER`.
- This is a native NT compatibility descriptor, not a second Linux ACL database. Linux VFS and Linux syscall permission decisions remain authoritative for Linux processes.

## Ownership

| Responsibility | Owner |
|---|---|
| selector and register order | `syscall::nt` |
| native NTDLL stub | `exec::pe_loader` |
| handle rights and descriptor construction | NT security adapter |
| identity source | scheduler credential snapshot |
| user-memory fault recovery | `uaccess` |

## Tests

- selector 64 and native export resolution are covered by host tests;
- both kernel architectures compile the target adapter;
- the normal Windows compatibility suite preserves Linux isolation and the Notepad graph rollback diagnostic.
