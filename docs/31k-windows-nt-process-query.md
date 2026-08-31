# Windows NT process query

FROZEN 2026-08-31. Dep:`01`,`02`,`13`,`31b`,`31d`,`31f`,`31h`,`52`,`53`. Provides: current-process basic information for the NT runtime.

## 1 Contract

- `NtQueryInformationProcess` is appended at NT service ID `21`; existing selectors remain stable.
- `ProcessBasicInformation` is the only initial information class.
- The current-process pseudo-handle is the only accepted process target until process-handle publication lands.
- PEB address, process ID, and parent process ID come from task-owned canonical state.
- The result is copied only after output length and user ranges are validated.

## 2 Ownership

| Responsibility | Owner |
|---|---|
| task-owned PEB address | `sched::Task` |
| process query ABI | `syscall::nt` |
| current-process result encoding | NT syscall adapter |
| process object handles | NT object layer, later milestone |

## 3 Tests

- service ID `21` decodes without renumbering prior NT services;
- the NTDLL runtime exports and resolves the query stub;
- unsupported information classes, non-current targets, short buffers, and invalid output pointers fail before writeback;
- PE exec publishes the task-owned PEB address used by the query path.
