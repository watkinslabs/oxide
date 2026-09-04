# Windows NT process query

FROZEN 2026-09-04. Dep:`01`,`02`,`13`,`31b`,`31d`,`31f`,`31h`,`52`,`53`. Provides: current-process and process-handle information for the NT runtime.

## 1 Contract

- `NtQueryInformationProcess` is appended at NT service ID `21`; existing selectors remain stable.
- `ProcessBasicInformation`, `ProcessVmCounters`, `ProcessAffinityMask`, `ProcessWow64Information`, `ProcessImageFileName`, `ProcessImageFileNameWin32`, and `ProcessHandleCount` are implemented; other classes remain explicitly unsupported.
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
| process handle count | `sched::ThreadGroup::nt_handles` |
| process VM accounting | `vmm::AddressSpace::accounting_snapshot` |

## 3 Tests

- service ID `21` decodes without renumbering prior NT services;
- the NTDLL runtime exports and resolves the query stub;
- unsupported information classes, non-current targets, short buffers, and invalid output pointers fail before writeback;
- `ProcessHandleCount` reports the live process-table handle count, including duplicates, with the 4-byte ABI and length mismatch ordering;
- `ProcessVmCounters` reports the exact 88-byte `VM_COUNTERS` and 96-byte `VM_COUNTERS_EX` layouts from the task's canonical mm accounting; virtual size includes every VMA, resident size uses RSS, pagefile usage uses anonymous plus swap pages, and the 32-bit page-fault field saturates;
- `ProcessVmCounters` accepts only 88 or 96 bytes for success, copies the available structure before returning `STATUS_INFO_LENGTH_MISMATCH` for other lengths at least 88, and reports the corresponding required length;
- PE exec publishes the task-owned PEB address used by the query path.
