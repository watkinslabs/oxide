# Windows user32 native adapter

Status: FROZEN  
Frozen: 2026-09-06

`windows-user32` owns the Win32-facing façade for the native window and
message services. It is a userspace component and enters the NT personality
through tagged service selectors; it never uses Linux syscall numbers to
implement Windows behavior.

## 1

- `CreateWindowExW`-style callers receive a native window identifier from the
  window service.
- Creation applies requested `WS_VISIBLE` only after `WM_NCCREATE` and
  `WM_CREATE` accept. A child requested visible must not remain hidden merely
  because its parent will be shown later. Rejected creation destroys any
  prepared desktop representation and returns NULL on the raw HWND ABI.
- `DestroyWindow`, `PostMessage`, `PeekMessage`, `GetMessage`, and the default
  window procedure preserve the existing NT window ABI.
- Class registration retains UTF-16 class names and window-procedure pointers
  in the process adapter; creating a window submits only the procedure pointer
  to the native window service.
- Window rectangles are read and written through the native window owner; the
  adapter retains no geometry shadow state.
- Raw NtUserCallHwndParam ordinal 0x1336 takes HWND, parameter pointer and
  method. Method 13 queries rectangles through a 16-byte structure containing
  RECT pointer u64, client BOOL u32 and requested DPI u32. Nonzero client
  requests local client bounds; zero requests screen-relative window bounds.
  Canonical client geometry and parent offsets supply results; no guessed
  dimensions replace missing state. Validate HWND, structure and destination;
  Stored NCCALCSIZE client bounds share the owning window rectangle's parent
  coordinate space. Parent-to-screen mapping adds the stored client origin
  once; frame-local client offset is client origin minus window origin.
  return TRUE only after complete 16-byte RECT copyout. DPI conversion uses
  canonical window/desktop awareness, not an independent fixed-geometry table.
- Creation classifies child parentage only when WS_CHILD is set and WS_POPUP
  is clear. Other supplied parent HWNDs describe top-level ownership, not
  child geometry. A child hMenu is a pointer-width control ID stored on the
  canonical HWND; it is not validated as an HMENU. Non-child hMenu remains
  a canonical menu handle. Control queries/mutations preserve pointer width.
- Class registration copies WNDCLASSEX.style into the canonical class before
  any HWND creation. Class DC ownership, clipping and resize damage consume
  that field; no per-window reconstruction or adapter-side style registry.
- Class registration retains cbWndExtra; each canonical HWND owns that many
  zero-initialized extra bytes. Nonnegative Get/SetWindowLong offsets address
  those bytes without alignment restrictions; the entire requested 2/4/8-byte
  field must fit. Invalid offsets return zero and ERROR_INVALID_INDEX without
  mutation. Set returns the previous field value; GetWindowLong truncates to
  32 bits while GetWindowLongPtr preserves pointer width.
- Window long storage includes canonical control/menu ID, instance, user data
  and window procedure; no adapter-side EDITSTATE registry. Raw class creation
  initializes extra storage before WM_NCCREATE, so control callbacks can store
  and retrieve their state immediately. HWND destruction frees the storage.
- Properties live inside each canonical owned HWND as atom, string/integer
  origin and pointer-width value. String SetProp interns in the existing atom
  owner; string GetProp/RemoveProp only look up existing atoms. Integer-resource
  names directly select the atom. Replacement updates value/origin; absent
  get/remove returns NULL, and removal returns the prior value. Destruction
  releases all window properties. UTF-16 usercopy precedes owner locking.
- Atom values are stable slot identities for the lifetime of each live atom.
  Releasing a property atom tombstones its slot; later allocation may reuse
  only that vacant slot and must never shift or retarget another live atom.
- Raw property ordinals are GetProp 0x1438/two arguments, RemoveProp
  0x151e/two and SetProp 0x157f/three; Set returns BOOL, get/remove HANDLE.
- Each admitted BeginPaint owns one canonical `PaintSession { damage, dc }` for
  the HWND. BeginPaint allocates a fresh canonical GdiManager paint DC and binds
  that exact handle into the WindowManager session; it does not reuse the
  stable window DC, create a second association table, or accept a
  caller-selected DC. EndPaint must match the HWND and exact session HDC before
  deleting that fresh paint DC, so an unrelated or forged HDC cannot be
  deleted. Window destruction and thread teardown consume any session and
  delete only its associated paint DC; failed PAINTSTRUCT copyout consumes the
  session and deletes that same DC.
- Raw window-long queries share NtUserCallHwndParam methods 9/10 (A/W long)
  and 11/12 (A/W pointer). SetWindowLongPtr takes HWND, signed index,
  pointer-width value and ANSI BOOL. Invalid HWND fails before field access.
- Message records remain caller-owned and use the fixed 64-bit layout from
  the shared NT ABI crate.
- `DispatchMessage` submits that shared record through the existing native
  callback transition and returns the window-procedure result.
- NtUserMessageCall has seven logical arguments: HWND, message, WPARAM,
  LPARAM, result-info pointer, callback selector, ANSI BOOL. Raw and descriptor
  paths read the selector at index 5 and ANSI at index 6; index 7 is never read.
- Same-thread SendMessage with client result-info publishes the canonical
  target procedure and message into the 72-byte win_proc_params record, then
  returns zero; the nonzero HWND tells user32 to execute its local dispatcher.
  GetDispatchParams uses the same record with dispatch mapping and BOOL result.
  Caller-supplied procedure input belongs only to CallWindowProc. Different
  threads execute through owner-thread sent-message work, never caller context.
- Parameter publication writes the HWND readiness field only after all other
  fields are copied successfully. ANSI source/destination modes are distinct;
  class registration flags retain destination encoding on canonical HWND state.

## 2

- BeginPaint admits a valid HWND even when its update region is empty, returns
  a fresh valid HDC and an empty rcPaint. Copyout occurs after releasing GUI
  ownership; failed copyout ends the paint reservation and deletes that HDC.
  Consumed update state is not restored. EndPaint with an empty region deletes
  its fresh paint DC and succeeds without presenting an empty frame. Raw HDC
  failures return NULL, never an NTSTATUS as a handle.
- A returned NT failure status is distinct from a host Linux transport error.
- `PeekMessage` reports an empty queue as an empty result.
- The adapter does not create a second window table or message queue.

## 3

- Hosted tests validate selector values, message layout, and failure decoding.
- Kernel integration remains covered by the existing native window tests.
