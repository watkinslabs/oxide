# Windows NT Set Process Information

Status: FROZEN

Date: 2026-08-31

## Contract

The native 64-bit `NtSetInformationProcess` export is selector 119. Wine
uses this service for process priority, affinity, execute flags, tokens,
instrumentation callbacks, and related process state. Oxide does not yet
expose a complete Windows process-information model for those classes, so
the service returns explicit `STATUS_NOT_IMPLEMENTED`.

Linux scheduling and process controls are not silently presented as Windows
process-information classes.
