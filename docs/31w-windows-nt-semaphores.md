# Windows native semaphore objects

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`52`,`53`. Provides: counting semaphore handles and wait integration.

## 1 Contract

- `NtCreateSemaphore` accepts a non-negative initial count no greater than a positive maximum.
- `NtReleaseSemaphore` rejects zero releases and count overflow, returning the previous count when requested.
- Semaphore handles are process-local NT objects with `SEMAPHORE_MODIFY_STATE` and `SYNCHRONIZE` access checks.
- Single and multiple waits consume semaphore permits through the scheduler wait predicate; event semantics remain unchanged.

## 2 Tests

- count consumption, release, and maximum enforcement;
- invalid creation bounds and release counts fail before object publication;
- semaphore handles participate in wait-any and wait-all selection;
- Linux event and futex paths remain untouched.
