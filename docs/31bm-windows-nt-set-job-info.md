# Windows NT Set Job Object Information

Status: FROZEN

Date: 2026-08-31

## Contract

The native 64-bit `NtSetInformationJobObject` export is selector 118. Wine
uses it for job limits and completion-port association. Oxide currently
tracks job handles and assignment validation but does not yet store those
limits or completion associations, so this service returns explicit
`STATUS_NOT_IMPLEMENTED`.

Linux cgroups and scheduler groups are not substituted for Windows job
objects.
