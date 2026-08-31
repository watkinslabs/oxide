# Windows native NT completion ports

Status: FROZEN  
Frozen: 2026-08-31

## Contract

- `NtCreateIoCompletion` creates a process-local queue-backed completion-port object.
- `NtSetIoCompletion` appends a fixed key/overlapped/status/information packet and wakes a waiter.
- `NtRemoveIoCompletion` removes one packet immediately or waits against a relative NT timeout.
- Completion-port handles enforce modify-state and synchronize access independently of Linux file descriptors.
- The queue is an NT object owned by the scheduler layer; asynchronous file producers remain a later adapter concern.
- Absolute NT wall-clock timeouts remain rejected by this initial native operation until the common time mapping is complete.

## Tests

- packet ordering and queue readiness are covered by scheduler object tests;
- malformed pointers, wrong object types, access masks, timeout behavior, and fixed ABI sizes are covered by NT decoder/adapter tests;
- native NTDLL exports are checked alongside the existing 64-bit PE loader tests;
- Linux syscall routing remains unchanged and both kernel architectures are checked.
