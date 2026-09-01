# Windows user32 native adapter

Status: FROZEN  
Frozen: 2026-09-01

`windows-user32` owns the Win32-facing façade for the native window and
message services. It is a userspace component and enters the NT personality
through tagged service selectors; it never uses Linux syscall numbers to
implement Windows behavior.

## 1

- `CreateWindowExW`-style callers receive a native window identifier from the
  window service.
- `DestroyWindow`, `PostMessage`, `PeekMessage`, `GetMessage`, and the default
  window procedure preserve the existing NT window ABI.
- Class registration retains UTF-16 class names and window-procedure pointers
  in the process adapter; creating a window submits only the procedure pointer
  to the native window service.
- Window rectangles are read and written through the native window owner; the
  adapter retains no geometry shadow state.
- Message records remain caller-owned and use the fixed 64-bit layout from
  the shared NT ABI crate.

## 2

- A returned NT failure status is distinct from a host Linux transport error.
- `PeekMessage` reports an empty queue as an empty result.
- The adapter does not create a second window table or message queue.

## 3

- Hosted tests validate selector values, message layout, and failure decoding.
- Kernel integration remains covered by the existing native window tests.
