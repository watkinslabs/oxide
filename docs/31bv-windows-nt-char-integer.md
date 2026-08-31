# Windows NT character integer conversion

Status: FROZEN
Date: 2026-08-31

`RtlCharToInteger` is implemented at the native NT boundary for the 64-bit
Windows personality. It accepts the documented bases 0, 2, 8, 10, and 16;
base zero recognizes lowercase `0b`, `0o`, and `0x` prefixes; leading ASCII
space/control characters and one sign are accepted; conversion stops at the
first invalid digit and stores the low 32 bits.

The adapter bounds its userspace string read and validates the destination
before publishing the result. Linux personality paths are unchanged.
