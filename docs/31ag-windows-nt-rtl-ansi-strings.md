# Windows native RTL ANSI strings

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: native ANSI descriptor initialization for Wine loader and registry helpers.

## Contract

- `RtlInitAnsiString` and `RtlInitAnsiStringEx` are append-only NT services `62` and `63`.
- Both write the x64 16-byte `STRING` layout: 16-bit `Length`, 16-bit `MaximumLength`, six bytes of padding, and a 64-bit source `Buffer`.
- The source is not copied. A null source produces zero lengths and a null buffer.
- The ordinary form records at most `0xfffe` bytes; the Ex form returns `STATUS_NAME_TOO_LONG` for a source beyond that representable length.
- User-memory faults return `STATUS_INVALID_PARAMETER` without publishing a partial descriptor.
- These services are available only through the NT personality; Linux syscall numbering and behavior are unchanged.

## Ownership

| Responsibility | Owner |
|---|---|
| selector and six-register ABI | `syscall::nt` |
| native NTDLL stubs | `exec::pe_loader` |
| bounded byte scan and descriptor write | NT RTL adapter |
| fault recovery | `uaccess` |

## Tests

- selectors 62 and 63 decode without renumbering existing services;
- the native runtime resolves both exports;
- ANSI source width and null/overlong contracts are covered by the target adapter tests;
- Linux ELF dispatch cannot enter the NT namespace.
