# Native NT syscall ABI

FROZEN 2026-08-31. Dep:`01`,`02`,`15`,`31c`,`53`. Provides: oxide-owned NT service decoding and a disjoint tagged entry word.

## 1 Contract

- NT calls use a separate service namespace from Linux syscall numbers.
- The tagged entry namespace is the high word `0x4e54_0000_0000_0000`; untagged Linux numbers are rejected.
- The ABI crate only decodes six machine-word arguments; it performs no work and imports no subsystem.
- Unknown service IDs fail before any subsystem state is fetched or changed.
- Service IDs are stable oxide ABI values; Windows build-specific NTDLL numbering is a userspace concern.
- Linux syscall dispatch and return conventions remain unchanged.
- The kernel exposes a separate `oxide_nt_syscall_dispatch` entry; NT task state
  is stored separately from Linux `personality(2)` flags.

## 2 Services

| ID | Service | Work owner |
|---:|---|---|
| 0 | allocate virtual memory | `exec::nt_memory` |
| 1 | free virtual memory | `exec::nt_memory` |
| 2 | protect virtual memory | `exec::nt_memory` |
| 3 | query virtual memory | `exec::nt_memory` |
| 4 | terminate process | `sched::exit` |
| 5 | create event | `sched::nt_object` |
| 6 | close handle | `sched::nt_object` |
| 7 | set event | `sched::nt_object` |
| 8 | reset event | `sched::nt_object` |
| 9 | wait for single object | `sched::nt_object` / scheduler wait loop |
| 10 | create file | `vfs` NT adapter |
| 11 | open file | `vfs` NT adapter |
| 12 | read file | `vfs` NT adapter |
| 13 | write file | `vfs` NT adapter |
| 14 | query file information | `vfs` NT adapter |
| 15 | set file information | `vfs` NT adapter |
| 16 | query directory | `vfs` NT adapter |
| 42 | create registry key request | NT registry adapter |
| 43 | open registry key request | NT registry adapter |
| 44 | query registry value request | NT registry adapter |
| 45 | set registry value request | NT registry adapter |
| 46 | lock file byte range | `vfs` NT adapter / inode record locks |
| 47 | unlock file byte range | `vfs` NT adapter / inode record locks |
| 48 | duplicate NT handle | `sched::nt_object` |
| 49 | create timer | `sched::nt_object` |
| 50 | set timer | `sched::nt_object` |
| 51 | cancel timer | `sched::nt_object` |
| 115 | query system information | native NTDLL system-information adapter |

## 3 Tests

- all defined IDs decode to the matching service;
- unknown IDs are rejected;
- arguments are preserved without truncation;
- each pointer-bearing memory service validates its Windows-shaped user pointers;
- the kernel-only adapter accepts only the current-process pseudo-handle and
  calls the shared VMM through typed arguments;
- event creation validates the native event type and optional prior-state
  pointers before publishing a process-local handle;
- close, set, and reset reject stale or insufficient handles before touching
  event state;
- wait validates `SYNCHRONIZE` access, supports null/infinite, relative, and
  absolute NT timeout encodings, and maps timeout/interruption statuses;
- file services validate their outer request record before nested user-memory
  or VFS work is attempted;
- the implemented file adapter supports existing-file open, create-on-missing,
  synchronous read/write, and common metadata query/set classes through the
  canonical VFS description; directory enumeration supports
  `FileNamesInformation` through the canonical VFS iterator;
- `FileRenameInformation` reuses the canonical VFS rename transaction after
  validating its copied UTF-16 record and maps `RENAME_NOREPLACE` from
  `ReplaceIfExists`;
- `FileDispositionInformation` requires `DELETE` access and arms or cancels
  the shared final-close deletion state;
- `NtLockFile` and `NtUnlockFile` use fixed 32-byte x86-64 records, validate
  flags and checked half-open ranges, and route to the inode-owned record-lock
  engine; nonblocking conflicts return `STATUS_LOCK_NOT_GRANTED`;
- `NtDuplicateObject` validates process scope, access reduction, output
  publication, same-access, and close-source options before changing the
  process-local NT handle table;
- Linux syscall ABI tests remain unchanged.
- `NtAccessCheck` is the one Windows-x64 service with more than six parameters:
  the six-register thunk supplies arguments 0..5 through this ABI, while the
  adapter reads arguments 6 and 7 from the preserved caller stack in the
  x86-64 entry frame. No global `SyscallArgs` or Linux entry layout changes.
- Registry records use fixed x86-64 layouts for `UNICODE_STRING`, `OBJECT_ATTRIBUTES`, and the four key/value requests; nested buffers are validated by the registry owner after the outer record is copied.
- `NtQuerySystemInformation` class `SystemWineVersionInformation` returns a bounded four-field native NTDLL identity record for Wine startup; it accepts only NT-personality callers and reports short buffers without writing partial state.
