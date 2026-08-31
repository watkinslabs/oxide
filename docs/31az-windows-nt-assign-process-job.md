# Windows NT Assign Process to Job

Status: FROZEN

Date: 2026-08-31

## Contract

Wine implements `NtAssignProcessToJobObject(job, process)` through the native
job-object server, validating both handles and applying the job's process
limits and notification state.

Oxide exposes the native 64-bit ABI as selector 103. Job objects are now a
distinct NT handle type, and assignment validates the job handle, access
mask, and current-process pseudo-handle. Resource-limit enforcement and
cross-process membership bookkeeping remain follow-up work; Linux process
groups and job-control state are never used as an alias.
