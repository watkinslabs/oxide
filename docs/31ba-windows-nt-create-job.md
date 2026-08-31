# Windows NT Create Job Object

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtCreateJobObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)`
for the native job-object path used by Win32 startup code. Oxide exposes the
64-bit ABI as selector 104 and returns a process-local handle whose object
type is `Job`. The handle table enforces the requested access mask and output
pointer validation.

This first implementation provides object identity and validation. Job
limits, notifications, and complete membership accounting are separate
semantics still required before general job-management compatibility. The
implementation does not reuse Linux process groups or alter Linux scheduling
behavior.
