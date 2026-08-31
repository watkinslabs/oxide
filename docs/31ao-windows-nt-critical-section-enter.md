# Windows NT critical-section acquisition and release

Status: FROZEN
Frozen: 2026-08-31

`RtlEnterCriticalSection` uses the 64-bit RTL critical-section fields for the
uncontended and recursive paths. Contended paths use a process-local native NT
mutant stored in `LockSemaphore`, so waiting remains owned by the scheduler's
canonical NT wait primitive rather than a second user-lock implementation.

`RtlLeaveCriticalSection` decrements recursive ownership in the same layout and
releases the native mutant when the final recursive level is left.
