# B3630 scrollbar sizegrip input

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0885 |

Actual control procedure now handles sizegrip WM_SETCURSOR through the existing
shared OEM cursor owner, choosing opposite diagonals for RTL and preserving
the entire previous cursor return. Ordinary scrollbar cursor still delegates
to the default procedure. Left-down/double-click sends canonical relative
parent WM_SYSCOMMAND with bottom-left/bottom-right sizing command and original
LPARAM. Existing resumable Send owns suspension; final control result is zero
regardless of parent response/failure. GUI lock is released before either
external owner runs. No parallel input/cursor/callback registry.

Actual procedure entry initially returns STATUS_NOT_IMPLEMENTED for cursor
(/tmp/B3630-sizegrip-red.log). Restoring missing click route also fails with
STATUS_NOT_IMPLEMENTED versus0 (/tmp/B3630-sizegrip-click-red.log). Corrected
joined boundary passes26 tests (/tmp/B3630-sizegrip-green.log), including
both directions, both click numbers, full-width cursor and LPARAM values,
suspended completion, failed callback, and ordinary cursor delegation.
Cursor installation and Send execution are explicit seams; tests assert GUI
is not held at either call. Existing real cursor/Send owners are reused;
these tests do not establish rendered pixels or full real User32 acceptance.

Build/features/stack validation ongoing. Ordinary scrollbar tracking, focus,
state messages and synchronous refresh remain KI0885; no full-procedure or
Notepad completion claim. No new boot.
