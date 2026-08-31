# Windows NT atom deletion

Status: FROZEN
Date: 2026-08-31

`RtlDeleteAtomFromAtomTable` removes a string atom from the canonical process
atom namespace. Integer atoms below the string-atom range are successful
no-ops; zero, unknown string atoms, and invalid table tokens return the
corresponding NT status. Deletion clears the existing slot so later atom
allocation can reuse its identifier without creating a second registry.

Linux atom syscalls and Linux personality paths are unchanged.
