# Windows native object query

FROZEN 2026-08-31. Dep:`01`,`02`,`31d`,`31f`,`31h`,`52`,`53`. Provides: the first handle metadata query used by the native runtime.

## 1 Contract

- `NtQueryObject` is appended at NT service ID `61`; existing selectors remain stable.
- `ObjectBasicInformation` is the initial supported class.
- The current process's NT handle table is canonical: stale or absent handles return `STATUS_INVALID_HANDLE`, and `GrantedAccess` comes from the live handle entry.
- The x64 result is the 56-byte `OBJECT_BASIC_INFORMATION` layout; unsupported pool, count, and creation-time fields are zero because the NT object owner does not expose those counters yet.
- Short output returns `STATUS_INFO_LENGTH_MISMATCH`; return length is published only through validated usercopy.
- Linux file descriptors and syscall routing remain untouched.

## 2 Tests

- selector `61` decodes without renumbering earlier services;
- the native NTDLL runtime resolves `NtQueryObject` into its mapped stub page;
- object-table access rights remain the source for `GrantedAccess`;
- stale handles, unsupported classes, short buffers, and invalid output pointers fail without partial output;
- the production Notepad graph no longer fails at this import once the adapter is present.
