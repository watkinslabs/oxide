# Windows NT Query Job Object

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtQueryInformationJobObject` for job limits, accounting, and
membership information. Oxide exposes the native 64-bit export as selector
113, but the current Job object does not yet maintain those information
classes, so the service returns an explicit unsupported NT status.

No Linux cgroup, process-group, or scheduler state is presented as Windows
job information.
