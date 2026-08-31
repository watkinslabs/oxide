# Windows NT RTL atom lookup

Status: FROZEN
Date: 2026-08-31

`RtlLookupAtomInAtomTable` searches the process-owned NT atom table without
creating an entry. Integer atoms pass through directly; counted UTF-16 names
use the same bounded ASCII-folding comparison and invalid-output handling as
atom insertion. Missing names return `STATUS_OBJECT_NAME_NOT_FOUND`.
