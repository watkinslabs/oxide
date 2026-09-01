# Windows NT callback return boundary

FROZEN 2026-09-01. Dep: 01,02,31fc,52,53. Exposes the native `NtCallbackReturn` status boundary.

The current NT entry path has no active user-mode callback frame, so the call returns `STATUS_NO_CALLBACK_ACTIVE`, matching the reference contract. Callback dispatch, frame stacking, return-buffer transfer, and callback-thread integration remain required for callback-producing services.
