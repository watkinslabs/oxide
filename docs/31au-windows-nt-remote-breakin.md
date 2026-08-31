# Windows NT Remote Break-In

Status: FROZEN

Date: 2026-08-31

## Contract

Wine implements `DbgUiIssueRemoteBreakin(process)` by creating a thread in
the target process at the native `DbgUiRemoteBreakin` entry point and closing
the returned thread handle.

Oxide exposes the native x64 export as selector 98 and preserves the NTSTATUS
boundary. The current foundation does not yet have cross-process NT thread
handles or the debugger event channel required to create the remote break-in
thread, so an NT caller receives `STATUS_NOT_IMPLEMENTED`; a non-NT caller or
missing current task receives `STATUS_INVALID_PARAMETER`. No Linux task or
Linux debugger state is modified by this route.
