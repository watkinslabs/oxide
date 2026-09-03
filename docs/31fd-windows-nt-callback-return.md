# Windows NT callback return boundary

FROZEN 2026-09-01. Dep: 01,02,31fc,52,53. Exposes the native `NtCallbackReturn` status boundary.

The NT entry path owns a bounded callback-continuation stack per executing
thread. Callback-producing services push the suspended instruction and stack
pointers before redirecting to user code; `NtCallbackReturn` pops the newest
continuation, copies the eight-byte LRESULT, and restores that frame. An empty
stack or invalid return length returns `STATUS_NO_CALLBACK_ACTIVE`. The stack
is independent of process-wide loader and window state, so nested WndProc
dispatches cannot overwrite a sibling continuation.
