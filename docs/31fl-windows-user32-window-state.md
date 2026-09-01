# Windows user32 window state

Status: FROZEN  
Frozen: 2026-09-01

The native window owner stores HWND parentage, UTF-16 title/control text,
client geometry, and visibility. `windows-user32` exposes the corresponding
Win32-shaped calls through tagged NT services; it owns no duplicate window
state.

## 1

- `SetWindowTextW` replaces a window's UTF-16 text through the native owner.
- `GetWindowTextW` copies at most `count - 1` UTF-16 units and terminates the
  destination when `count` is non-zero; its result is the copied length.
- `GetClientRect` returns client coordinates with origin `(0, 0)` and the
  current window width and height.
- `GetParent` returns the native parent HWND or zero for a top-level window.
- `ShowWindow` updates native visibility and returns the previous state.
- Destroying a window removes its text and all other owned state.

## 2

- A missing or non-canonical HWND is rejected before state access.
- Text input is copied until its required UTF-16 terminator; unterminated
  input is rejected at the bounded service limit.
- Parentage and text remain in the native `WindowManager`; no adapter shadow
  table is permitted.

## 3

- Hosted IPC and user32 tests cover text lifecycle, parentage, client geometry,
  visibility transitions, selector values, and buffer boundaries.
- The ordinary Windows compatibility gate and both kernel architecture builds
  cover integration.
