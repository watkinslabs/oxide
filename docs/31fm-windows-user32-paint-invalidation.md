# Windows user32 paint invalidation

Status: FROZEN  
Frozen: 2026-09-01

The native window owner tracks dirty client regions and the user32 façade
exposes invalidation and paint-region consumption. Display-driver scanout stays
owned by the existing Linux DRM/framebuffer stack.

## 1

- `InvalidateRect` records a supplied client rectangle or the full client area.
- Repeated invalidation for one window coalesces into one bounding region and
  one `WM_PAINT` notification.
- `BeginPaint` consumes the pending region and copies it to the caller.
- `BeginPaint` opens one canonical per-window paint transaction, including
  when no update region is pending; a second begin is rejected until `EndPaint`.
- `EndPaint` validates the HWND and closes that transaction boundary; an
  unmatched end is rejected and cannot silently acknowledge a paint.
- Destroying a window removes its pending dirty region.

## 2

- Dirty state is part of the canonical native `WindowManager`; user32 has no
  parallel invalidation table.
- Invalid HWNDs fail before dirty-state access.
- Client coordinates are distinct from screen-space window rectangles.
- The contract does not claim scanout or font rasterization; those are separate
  display and GDI owners.

## 3

- Hosted IPC tests cover coalescing, paint consumption, and paint notification.
- User32 tests cover tagged selector stability.
- The normal compatibility gate and both kernel architecture builds cover the
  native dispatch integration.
