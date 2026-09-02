# Windows window and message core

FROZEN 2026-08-31. Dep:`31g`,`31s`,`46`,`52`,`53`. Provides: the first kernel-owned state core for Wine `win32u` window handles and per-thread message queues.

## 1 Contract

- Window handles are monotonic and are never immediately reused as another window.
- A window records its owning NT thread, parent, window procedure address, and visibility state.
- Parent handles are validated at creation and stale handles fail closed.
- Message queues preserve FIFO order for unmatched messages and support HWND plus inclusive message-range filters with peek/remove behavior.
- Queue capacity is bounded at 10,000 messages; overflow is reported rather than silently dropping input.
- The initial default procedure policy requests destruction for `WM_CLOSE`, reports `HTCLIENT` for `WM_NCHITTEST`, and returns zero for otherwise unhandled messages.
- The core is pure state; task lookup, blocking, display composition, and Linux evdev translation remain adapters.

## 2 Wine relationship

This is the kernel-side state owner for the `NtUserCreateWindowEx`, `NtUserPostMessage`, `NtUserPeekMessage`, and `NtUserGetMessage` boundary used by Wine `win32u`. The existing Linux input stack remains the source of physical input events.

## 3 Tests

- filtered peek/remove preserves unmatched FIFO messages;
- stale and invalid parent window handles fail closed;
- handles remain monotonic after destruction;
- default close/hit-test policy is deterministic;
- the module is included in the normal IPC/Windows compatibility test suite.

## 4 Wine class registration

Wine `NtUserRegisterClassExWOW` registrations are decoded at the native
ordinal boundary and stored in the process-scoped window manager. Class names
use bounded UTF-16 reads and case-insensitive matching; the retained WndProc
address is selected when Wine creates a window through `NtUserCreateWindowEx`.
Direct native window creation continues to accept an already-resolved
procedure address. Duplicate or malformed class registrations fail before
window allocation.
