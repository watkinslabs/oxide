# Windows thread-handle targets

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31f`,`31k`,`31m`,`52`,`53`. Provides: NT thread-handle resolution for query and termination.

## 1 Contract

- `NtQueryInformationThread` accepts the current-thread pseudo-handle or a live process-local thread handle.
- A real handle must grant `THREAD_QUERY_INFORMATION`; wrong type, stale generation, and missing rights fail before output copyout.
- `NtTerminateThread` accepts the current-thread pseudo-handle or a live process-local thread handle with `THREAD_TERMINATE`.
- A thread handle cannot target a different NT process; process-local NT handle tables remain owned by the thread group.
- Current-thread termination uses the existing direct exit path; another thread receives a forced-fatal Linux signal through the canonical scheduler signal owner.

## 2 Tests

- handle generation and access masks remain enforced by the single NT handle table;
- query and termination reject wrong object kinds, stale handles, insufficient rights, and cross-process targets;
- real thread objects retain their canonical scheduler task until handle close;
- both architecture kernel checks compile identical target resolution and signal routing.
