# Windows NT Set Job Object Information

Status: FROZEN

Date: 2026-08-31

## Contract

The native 64-bit `NtSetInformationJobObject` export is selector 118. Wine
uses it for job limits and completion-port association. Oxide stores the
basic and extended limit classes in the scheduler-owned job object, validates
the exact 64-bit structure sizes and class-specific valid flags, and keeps
completion-port association explicit until its existing completion-port
owner is extended for job notifications.

Linux cgroups and scheduler groups are not substituted for Windows job
objects.
