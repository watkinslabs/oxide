# Windows NT object handles

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31d`,`52`,`53`. Provides: process-local NT object identity, access masks, handle generations, and lifetime rules.

## 1 Contract

- An NT handle is separate from a Linux file descriptor.
- A handle resolves only in the owning process's table.
- A handle carries a granted access mask; callers cannot duplicate it with additional rights.
- Closing a handle removes it before releasing the referenced object.
- Reusing a slot changes its generation, so a stale handle never resolves a new object.
- Clone-threads share one table through `ThreadGroup`; forked processes receive a new table.
- Object references use `Arc` lifetime ownership; subsystem state owns the object identity and behavior.
- File objects retain the canonical `Arc<vfs::File>` open description; NT
  handles do not duplicate VFS cursor, backend, or lifetime state.
- File handle access masks are checked before every read/write; an existing
  handle with insufficient rights returns access denied rather than invalid
  handle.

## 2 Object kinds

| Kind | Initial owner |
|---|---|
| process, thread | `sched` |
| file, directory | `vfs` adapter |
| section | `exec`/VMM adapter |
| event, semaphore, mutant, timer | native synchronization layer |
| completion port | I/O layer |
| token | security layer |

## 3 Tests

- object type and identity survive handle lookup;
- missing access rights fail lookup;
- close invalidates the old generation before slot reuse;
- duplicate rejects access escalation and preserves the object reference;
- the table is process-owned and is not the Linux fd table.
- a VFS-backed file handle preserves the shared open description through close;
  no second cursor or backend is created.
- create/open file requests use the existing parent resolver and VFS create/open
  path, preserving Linux permission and dentry publication rules.
- file metadata and cursor changes operate on the retained VFS inode/file
  description rather than shadow NT state.
- `FILE_DELETE_ON_CLOSE` is attached to the NT file object, so duplicate
  handles defer one deletion until their final object reference closes.
- `FileDispositionInformation` changes that same shared pending-delete state,
  rather than creating per-handle deletion flags.
- `NtDuplicateObject` supports same-access and reduced-access duplication,
  optional source closing, and preserves the shared object reference.
- directory handles retain the VFS readdir cursor while NT name records are
  packed into the caller's buffer.
