# Windows thread-handle targets

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31f`,`31k`,`31m`,`52`,`53`. Provides: NT thread-handle resolution for query and termination.

## 1 Contract

- `NtOpenThread` resolves a non-zero `CLIENT_ID` through the canonical scheduler registry, verifies that the thread belongs to the named process, and installs a process-local thread handle.
- `NtQueryInformationThread` accepts the current-thread pseudo-handle or a live process-local thread handle.
- A real handle must grant `THREAD_QUERY_INFORMATION`; wrong type, stale generation, and missing rights fail before output copyout.
- `NtTerminateThread` accepts the current-thread pseudo-handle or a live process-local thread handle with `THREAD_TERMINATE`.
- A thread handle remains process-local to the opener, but may reference a
  thread in another NT process after `CLIENT_ID` ownership validation.
- Current-thread termination uses the existing direct exit path; another thread receives a forced-fatal Linux signal through the canonical scheduler signal owner.

## 2 Tests

- handle generation and access masks remain enforced by the single NT handle table;
- `NtOpenThread` rejects zero/out-of-range IDs, mismatched process/thread IDs,
  stale scheduler IDs, Linux-personality targets, and unknown access bits;
- a valid remote NT thread produces a handle carrying the requested access and
  implicit synchronize right;
- query and termination reject wrong object kinds, stale handles, insufficient rights, and cross-process targets;
- real thread objects retain their canonical scheduler task until handle close;
- both architecture kernel checks compile identical target resolution and signal routing.

`ThreadGroupInformation` (class 30) returns one native 64-bit group-affinity
record: the task's effective CPU mask in `Mask`, group zero, and zero reserved
fields. The result uses the same handle target and query-rights validation as
basic thread information.

## 3 Query classes

The native query adapter exposes the Wine startup classes backed by task-owned
state:

| class | result | owner |
|---:|---|---|
| 9 | Win32 start address | `Task::nt_start_address` |
| 16 | I/O-pending indication | scheduler I/O-wait state |
| 20 | terminated flag | terminal `TaskState::Zombie` |
| 30 | group affinity | effective task CPU mask |
| 35 | suspend depth | `Task::nt_suspend_count` |

Every class validates the exact native output size, target handle, and query
right before writing user memory. Thread entry publication occurs when the
native NT thread is constructed, so the reported address cannot drift from the
entry used by the scheduler.
