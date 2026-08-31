# Windows NT `NtTerminateJobObject`

Status: FROZEN
Date: 2026-08-31

Native selector `122` accepts a native job handle and termination status. The
handle table validates `JOB_OBJECT_TERMINATE` access and the object type before
any process state changes.

The current NT job contract permits assignment of the calling process through
`NtAssignProcessToJobObject`. An empty job terminates successfully without
affecting the caller. When the caller is assigned to the specified job, the
service clears the membership marker and enters the canonical Linux
`exit_group` teardown path with the supplied status. No Linux job-control
state is repurposed.

The Windows workload and PE machine code remain x86-64-only. AArch64 checks
cover shared selector and ABI compilation, not Windows execution.
