# Windows NT thread lifecycle

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31b`,`31d`,`31f`,`31l`,`52`,`53`. Provides: current-thread identity and termination for the NT personality.

## 1 Contract

- `NtTerminateThread` is appended at NT service ID `23` and routes to Linux per-thread exit semantics.
- `NtQueryInformationThread` is appended at NT service ID `24`; `ThreadBasicInformation` is the initial class.
- Only current-thread pseudo-handle targets are accepted until general thread-handle targeting is complete.
- TEB, process ID, and thread ID are task-owned values; no parallel thread registry is consulted.
- Short buffers, unsupported classes, and invalid output pointers fail before writeback.

## 2 Ownership

| Responsibility | Owner |
|---|---|
| thread termination | existing scheduler/Linux `do_exit` path |
| TEB identity | `sched::Task` |
| query ABI and result encoding | NT syscall adapter |
| bootstrap exports | `exec::pe_loader` |

## 3 Tests

- service IDs `23` and `24` decode without renumbering earlier services;
- both NTDLL exports resolve to executable bootstrap stubs;
- current-thread basic information uses task-owned TEB/TID state;
- non-current targets and unsupported classes are rejected;
- Linux thread exit behavior remains the sole teardown implementation.
