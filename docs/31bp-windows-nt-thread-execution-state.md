# Windows NT `NtSetThreadExecutionState`

Status: FROZEN
Date: 2026-08-31

Native selector `121` implements the two meaningful arguments: execution-state
mask in register zero and writable prior-state pointer in register one. The
service is available only to NT-personality callers and rejects a null or
invalid prior-state pointer before changing state.

The compatibility state starts with `ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
| ES_USER_PRESENT`. Each call returns the previous mask. State is replaced
only when the previous mask lacks `ES_CONTINUOUS` or the new mask includes it;
otherwise the prior mask remains active. This mirrors the observable NT
contract while leaving Linux host power policy unchanged.

The AArch64 kernel check covers shared ABI wiring only. The Windows workload
and its PE machine code remain x86-64-only.
