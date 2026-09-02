# Windows native window/message ABI

FROZEN 2026-08-31. Dep:`31d`,`31t`,`46`,`52`,`53`. Provides: typed NT selectors for the first Win32 window and message operations.

## 1 Contract

- Selectors `27..31` represent create, destroy, post, peek, and get message operations; selector `32` is the shared native default-window procedure used by Wine's A/W forwarders.
- The syscall crate validates pointer shape and preserves scalar Windows values; it owns no window registry or queue state.
- `NtWindowMessage` is a fixed 32-byte x64 record: HWND, message, padding, WPARAM, LPARAM.
- Window state remains owned by the IPC window core; task ownership, blocking, copyout, and dispatch are syscall adapters.
- Unknown selectors and invalid message pointers fail before any state lookup or mutation.
- Existing Linux syscall numbers and Linux input behavior are unchanged.

## 2 Wine relationship

The shape follows the arguments consumed by Wine `win32u`'s `NtUserCreateWindowEx`, `NtUserPostMessage`, `NtUserPeekMessage`, and `NtUserGetMessage` wrappers while keeping the kernel-facing first slice intentionally smaller and typed.

## 3 Tests

- selectors `27..31` decode through the tagged NT namespace;
- post preserves HWND/message/WPARAM/LPARAM values;
- peek/get reject invalid output pointers;
- the default-window procedure preserves the four scalar arguments and applies the core close/hit-test policy;
- the window state core continues to test handle lifetime and queue filtering;
- Linux ABI tests remain unchanged.

## 4 File handoff invariant

`wine_server_handle_to_fd` validates the requested access mask against the
canonical NT handle entry, then allocates a new Linux fd referencing the same
VFS open-file description. It never aliases an existing descriptor number;
the caller owns the returned fd and its close lifetime independently. Failed
copyout closes the newly allocated descriptor before returning the error.
