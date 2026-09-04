# Windows NT `NtSetInformationThread`

Status: FROZEN
Date: 2026-08-31

The native service namespace reserves selector `120` for the six-argument
`NtSetInformationThread` ABI exported by the synthetic native NTDLL page.
The x86-64 Wine Notepad dependency graph reaches this export after the
process-information boundary.

The `ThreadAffinityMask` class (5) is implemented. Its pointer-sized input is
validated exactly, intersected with the task's canonical cpuset and active CPU
mask, rejected if empty, and published through the scheduler affinity owner.
Other thread-information classes remain an explicit `STATUS_INVALID_PARAMETER`
boundary; Linux scheduler state is not exposed as a substitute for them.

The AArch64 kernel build checks this shared selector and ABI wiring only; it
does not claim native execution of this x86-64 PE workload on ARM.

## Tests

- affinity narrowing, empty active intersections, and structurally unmodifiable
  tasks are hosted-tested;
- x86_64 and AArch64 target checks compile the native adapter and scheduler
  publication path;
- the installed Wine Notepad graph identifies this export as the frontier.
