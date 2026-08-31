# Windows NT NtAddAtom

Status: FROZEN

Date: 2026-08-31

## Contract

`NtAddAtom` copies a bounded UTF-16 atom name from the caller, allocates a
process-local string atom in the Windows string-atom range (`0xc000` onward),
reuses the existing ID for duplicate names, and writes the `RTL_ATOM` through
uaccess. The table is shared by NT threads in one `ThreadGroup` and isolated
from Linux processes. Invalid pointers, odd/empty names, names over 255 UTF-16
characters, and non-NT callers return `STATUS_INVALID_PARAMETER`; exhaustion
returns `STATUS_NO_MEMORY`.

The native 64-bit NTDLL export is selector 102. Deletion, lookup, and global
atom-table APIs remain separate follow-on surfaces.
