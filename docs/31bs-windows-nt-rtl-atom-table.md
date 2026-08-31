# Windows NT RTL atom table

Status: FROZEN
Date: 2026-08-31

`RtlAddAtomToAtomTable` uses the process-wide NT atom storage already owned by
the `ThreadGroup`. The opaque userspace table pointer is validated as a
non-null ABI token; it does not create a second kernel registry. Names are
bounded UTF-16 strings, integer atoms are returned directly, and duplicate
names match case-insensitively for ASCII code units while retaining the first
stored spelling.

The output atom pointer is copied before a new entry is committed, preserving
the table on a bad userspace destination. Atom allocation and lookup remain
under the existing process atom lock. Linux atom syscalls and Linux
personality paths are unchanged.
