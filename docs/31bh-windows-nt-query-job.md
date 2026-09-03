# Windows NT Query Job Object

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtQueryInformationJobObject` for job limits, accounting, and
membership information. Oxide exposes the native 64-bit export as selector
113. Basic-limit, extended-limit, and basic-accounting queries are owned by
the scheduler job object; unsupported information classes still return an
explicit NT status.

No Linux cgroup, process-group, or scheduler state is presented as Windows
job information.
