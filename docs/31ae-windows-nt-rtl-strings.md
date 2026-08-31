# Windows native RTL Unicode strings

FROZEN 2026-08-31. Dep:`01`,`02`,`31d`,`31h`,`52`,`53`. Provides: the first native RTL string descriptor operation.

## 1 Contract

- `RtlInitUnicodeString` and `RtlInitUnicodeStringEx` are appended at NT service IDs `59` and `60`; earlier selectors remain stable.
- The target is a 16-byte x64 `UNICODE_STRING` descriptor: `Length`, `MaximumLength`, six bytes padding, and a 64-bit source `Buffer`.
- A null source writes zero lengths and a null buffer.
- A non-null source is scanned as UTF-16 code units through exception-table usercopy; length is capped at `0xfffc` bytes and maximum length is length plus one UTF-16 terminator.
- The source bytes are not copied into a new allocation; the descriptor points at the caller's source buffer.
- The `Ex` form returns `STATUS_NAME_TOO_LONG` and leaves the target unchanged when the source exceeds `0xfffc` bytes; the non-`Ex` form caps the recorded length.
- Invalid target or source memory returns `STATUS_INVALID_PARAMETER` and does not publish a partial descriptor.
- This path is NT-personality-only; Linux ELF syscall routing is unchanged.

## 2 Ownership

| Responsibility | Owner |
|---|---|
| tagged selector and argument order | `syscall::nt` |
| native NTDLL stub address | `exec::pe_loader` |
| UTF-16 scan and descriptor write | NT syscall adapter |
| user-memory fault recovery | `uaccess` |

## 3 Tests

- selectors `59` and `60` decode without renumbering earlier services;
- the native runtime resolves both routines into its mapped stub page;
- target/source faults are rejected before successful publication;
- null, terminated, and overlong sources produce the documented descriptor lengths;
- the routine remains absent from Linux syscall-number dispatch.
