# Windows NT `NtSetInformationThread`

Status: FROZEN
Date: 2026-08-31

The native service namespace reserves selector `120` for the six-argument
`NtSetInformationThread` ABI exported by the synthetic native NTDLL page.
The x86-64 Wine Notepad dependency graph reaches this export after the
process-information boundary.

Wine supports thread-information classes including priority, affinity/group,
impersonation, ideal processor, and thread name. Oxide does not yet have the
corresponding Windows thread-information model or validated buffer contracts.
Linux scheduler and affinity state must not be silently substituted for those
Windows semantics. Until that state and its ABI tests exist, the service
returns `STATUS_NOT_IMPLEMENTED` for an NT-personality caller and remains an
explicit graph boundary.

The AArch64 kernel build checks this shared selector and ABI wiring only; it
does not claim native execution of this x86-64 PE workload on ARM.
