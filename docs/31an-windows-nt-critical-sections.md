# Windows NT critical-section lifecycle

Status: FROZEN
Frozen: 2026-08-31

The native NTDLL surface exposes `RtlDeleteCriticalSection` for the 64-bit
RTL critical-section layout. It resets the lock count, recursion, owner,
semaphore, and debug pointer through the user-access boundary. Acquisition
and waiter scheduling remain owned by the broader NT synchronization layer;
this operation does not create a second lock implementation.
