# Windows NT atom table creation

Status: FROZEN
Date: 2026-08-31

`RtlCreateAtomTable` initializes the process atom-table handle expected by the
Wine-derived NTDLL path. The returned value is an opaque nonzero userspace
token; atom names and IDs remain owned by the canonical `ThreadGroup` atom
state used by the native NT atom operations. Repeated initialization follows
the reference contract: an already initialized table succeeds for size zero
and rejects a nonzero requested size.

The hash-size argument is accepted as an allocation-policy hint but does not
create a second registry or duplicate atom namespace. Invalid destinations and
non-NT callers receive invalid-parameter status. Linux atom behavior is
unchanged.
