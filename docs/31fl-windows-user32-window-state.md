# Windows user32 window state

FROZEN 2026-09-06. Dep:`01`,`02`,`29a`,`31h`,`31fj`,`52`,`53`.

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
- Raw window placement uses a 44-byte little-endian WINDOWPLACEMENT: length@0, flags@4, showCmd@8, min-point@12, max-point@20, normal RECT@28.
- Set placement copies and validates the full structure and canonical HWND before mutation; normal placement uses existing geometry and ShowWindow owners, outside GUI locks for compositor acknowledgement.
- Raw placement preserves supplied normal coordinates without adding/subtracting workarea origins. Wholly offscreen normal rectangles move onto the selected real workarea with size preserved; monitor snapshots remain authoritative.
- SW_SHOWNORMAL and SW_SHOWDEFAULT restore normal geometry and request canonical visibility. Default show uses process startup parameters when enabled, otherwise SW_SHOWNORMAL.
- Adapters never invent minimized/maximized geometry or store placement in a second registry. Requests requiring unavailable canonical minimized/maximized state fail before mutation.
- Raw Set/Get placement return BOOL; ShowWindow returns previous visibility. Native NTSTATUS failures are mapped to FALSE, including publication failures; zero previous visibility is a successful ShowWindow result for Set placement.
- Get placement reports normal show state for a normal window even when hidden; showCmd is not a visibility bit. Unset min/max positions are (-1,-1).
- Raw Get requires caller length=44 and returns TRUE only after complete copyout; invalid length or HWND cannot modify the output structure.
- Raw SetWindowPos takes seven arguments including UINT flags; NOMOVE/NOSIZE preserve canonical origin/extents, negative requested extents become zero, requested coordinates clamp to signed 16-bit range and extents to 0..32767 before transport validation.
- NOZORDER ignores insertion HWND; otherwise insertion names a canonical sibling or TOP/BOTTOM/TOPMOST/NOTOPMOST. A valid non-sibling insertion returns TRUE without mutation; invalid insertion returns FALSE.
- SHOW/HIDE suppress redundant transitions using canonical visibility; both flags hide an already visible window and show a hidden window. Position requests retain redraw, activation, frame, callback, owner-order and asynchronous flags for canonical execution; adapters must not discard these semantics.
- Position commit owns geometry, ordering, visibility, activation and window-position notifications in the canonical window subsystem; publication waits occur outside GUI/GDI locks. Native failures return FALSE, never NTSTATUS-shaped TRUE.
- Position callbacks use a 40-byte WINDOWPOS (64-bit handles@0/8, signed geometry@16/20/24/28, flags@32). NCCALCSIZE uses three RECTs and an aligned pointer to embedded WINDOWPOS; user-pointer relocation completes before callback installation.
- Canonical HWND client bounds retain NCCALCSIZE output. Synchronous position transactions belong to the canonical process GUI entry, are bounded to 64 pending callbacks, and validate current thread/token on completion; callback-provided HWND replacement is rejected.
- NCCALCSIZE snapshots canonical class style before calling WndProc. CS_HREDRAW/CS_VREDRAW contribute WVR_HREDRAW/WVR_VREDRAW; each axis redraw bit clears when that client extent is unchanged. WVR_REDRAW prevents preservation. WVR_VALIDRECTS clips returned destination/source rectangles to new/old clients and equalizes their extents with top-left alignment; otherwise alignment flags select preserved edges of the overlapping client extents. NOCOPYBITS, NOREDRAW, SHOWWINDOW and HIDEWINDOW suppress preservation. Retained pixels move through canonical GDI backing before publication; canonical damage includes newly uncovered destination coverage and preserves pending invalid coverage rather than validating stale pixels.
- Position backing updates retain final SWP flags through GUI commit and GDI mutation. NOREDRAW resizing changes canonical storage/shared DC dimensions without creating rendered-output demand on a clean backing; existing pending output clips to the new extent, never expands to newly exposed coverage. Resizing advances output generation even without redraw, preserves outstanding submission ownership until completion, and rejects stale acknowledgements clearing newer output. NOREDRAW suppresses valid-bit copying, not geometry changes; it promises no pixel retention across storage replacement. Ordinary redraw resizing requests full nonempty backing output. Unchanged backing geometry/content does not manufacture an output generation.
- Cross-thread ASYNCWINDOWPOS requests execute on the canonical HWND owner thread through a bounded process GUI inbox and return admission success. No caller-thread execution of another thread's WndProc. Owner-thread message retrieval drains internal requests independent of application message filters and resumes its original retrieval after callback completion.
- Interrupted retrieval stores the original NtCall and raw-BOOL/tagged-NTSTATUS convention in a bounded nested stack keyed by thread. Callback completion pops the top matching-thread context and resumes dispatch; nested WndProc retrieval cannot overwrite the outer context. Immediate internal work retries retrieval without recursive resume.
- Synchronous cross-thread positioning waits for an owned reply cell without an invented timeout; waiting senders service incoming internal position requests. Nested callback completion resumes the suspended send or retrieval according to its saved continuation. Owner exit/destruction publishes FALSE and wakes senders; reply completion is single-assignment.
- Remote internal work is serviced before application filters and included in the sleep predicate. Raw GetMessage returns 1 for a normal message, 0 for WM_QUIT, and -1 for error; tagged retrieval retains NTSTATUS. Position completion BOOL is never used as the retrieval result.
- Popup ownership is distinct from child parentage and stored on the canonical HWND. Reordering preserves owned popups above owners, retains the topmost band and publishes resulting canonical sibling order rather than the unadjusted insertion request.
- Thread exit, HWND destruction and callback abandonment cancel matching pending/inbox work and wake synchronous senders with FALSE. Process GUI teardown drops remaining work; completion tokens cannot consume another thread's transaction.
- Canonical thread GUI teardown removes thread-owned HWNDs plus their child/owned-popup closure, including cross-thread descendants, before thread retirement. Existing destruction clears per-HWND geometry/text/paint/focus/capture/timers; teardown also removes the exiting thread's queue and thread timers and returns every removed HWND for transport/callback cancellation.
- Same-process cross-thread SendMessageW admits immutable HWND/message/WPARAM/LPARAM work against the canonical HWND owner thread. Queued plus active sends share a 64-request bound; no caller-thread execution of the recipient WndProc, application-message injection, or duplicate HWND registry.
- Sent-message replies retain the entire 64-bit LRESULT with separate pending/completed/cancelled state; zero, all-ones and 0x103 are valid results, not transport sentinels. A reply publishes once, after recipient callback completion; failed admission, revoked destination and callback installation failure return zero without reporting execution.
- Sent work runs before Get/Peek application filters and participates in message-wait readiness. Synchronous sends wait without a guessed timeout and service incoming sent work; saved continuations distinguish retrieval from nested send/position waits. Callback completion resumes the interrupted operation, never substitutes recipient LRESULT for retrieval status.
- Send and synchronous position transactions share the same reply primitive and wait loop. Both inboxes participate in pumping/readiness; existing pending-position state retains the interrupted shared reply across callbacks, with no auxiliary waiter registry or pointer-encoded continuation.
- Internal same-owner positioning optionally retains a caller token/function in the existing pending-position transaction. Its typed result separates completed BOOL, failure and callback installation; immediate results do not invoke the continuation. Final callback completion or window cancellation resumes the original owner-thread caller exactly once after all position callbacks; thread exit drops the continuation without running code on a retiring thread.
- Internal resumable send reports Completed LRESULT, Failed or Pending separately. Its owned reply retains an optional caller token/function continuation, invoked only on the sender after callback suspension; valid zero/0x103/all-ones results remain successful values. Immediate outcomes return directly to the caller; cancellation resumes a surviving sender with failure and cannot consume another thread's continuation.
- Thread/window revocation fails queued sends immediately. Active sends are marked canceled but cannot publish failure until recipient callback return or recipient exit; otherwise sender cleanup could free resources still used by WndProc. Sender exit detaches its continuation while retaining active recipient work; the existing paint queue retains retired resource payloads until that work ends, then disposes outside GUI without resuming the dead sender. Same-process pointer parameters remain in the shared address space; cross-process marshalling requires a separate validated transfer contract and cannot reuse those pointers.

## 2

- Canonical HWND state owns horizontal/vertical scroll ranges, page, position,
  arrow-disabled/visible state and live tracking state. SCROLLINFO accepts
  size 24 or 28 and supported SIF flags; only requested output fields change.
  Set ignores SIF_TRACKPOS input; Get returns live tracking position or current
  position when no tracking transaction exists. Signed-negative page values
  clamp to zero; other pages clamp to range length. Reversed or >=2^31-wide
  ranges become (0,0); position clamps to min..max-max(page-1,0).
- SetScrollInfo returns current position, or previous position for
  SIF_RETURNPREV. No-scroll ranges hide the nonclient scrollbar unless
  SIF_DISABLENOSCROLL requests disabled arrows. Page-only changes do not force
  visibility. Redraw flags retain their drawing effect in the canonical owner.
  SB_CTL uses synchronous scrollbar-window messages, not another nonclient bar.
- Raw SetScrollInfo ordinal 0x1581 has four arguments. GetScrollInfo uses
  NtUserCallHwndParam method 7 and a 16-byte bar/pointer descriptor. All input
  usercopy and size/mask validation precede owner mutation; output follows
  snapshot outside locks. Window destruction removes its scroll state.
- Nonclient scrollbar raster consumes copied canonical scroll state and
  window-relative bounds, system-color snapshots and DPI metrics. It paints
  arrows, track, proportional thumb and disabled/pressed states into the real
  DC, honoring surface/application/paint clipping. Short bars reserve four
  track pixels; normal arrows use scrollbar metrics; proportional thumb minimum
  is 17 pixels scaled by DPI. Disabled-both suppresses the thumb.
- Hidden, clipped and painted outcomes are distinct. Hidden is not evidence
  that old pixels were erased. Visibility changes update canonical window style
  and execute frame recalculation/repaint; raster success alone cannot complete
  SetScrollInfo. Presentation and callbacks occur after owner locks drop.
- Caret state is per GUI message queue, keyed by owner TID; it is not process
  global and cannot be changed through an HWND owned by another TID. Create
  replaces the caller queue's caret after validating HWND ownership, retains
  the prior client position when replacing the same HWND, resets dimensions,
  starts with hide depth one and off state; Destroy clears it. SetCaretPos
  stores signed client coordinates and turns the caret on only when the
  position changes, but cannot display it before the first ShowCaret. ShowCaret
  and HideCaret accept null HWND as the current queue caret; non-null HWND must
  name that caret and be owned by the caller. ShowCaret decrements hide depth
  and requests on; HideCaret increments hide depth and requests off. Visible
  requires an HWND, on state and zero hide depth. Repeated show/hide is
  saturating and retains canonical state.
- Caret updates publish after the queue lock drops to the compositor/raster
  owner with owner TID, HWND, old/new client rectangles, old/new visibility and
  a monotonic generation. A visible move erases the old pixels before painting
  the new pixels; destroy erases without painting. Renderer failure returns
  FALSE and never reports a fabricated success. Caret bitmap creation and
  actual pixel ownership remain with the GDI/compositor owner.
- Caret blink timing is owned by each message queue as one deadline, not by a
  backend timer or adapter registry. The default interval is 500 ms, matching
  the `CursorBlinkRate` fallback; the system-parameter owner supplies any
  configured interval in milliseconds. Visible position/show transitions arm
  the deadline, hide/destroy/window teardown clear it, and expiry reschedules
  the next interval while returning a typed `(owner_tid, hwnd, generation)`
  commit. Retrieval pumping consumes expired commits under GUI ownership, then
  applies the toggle through the canonical caret owner and publishes outside
  GUI locks. A stale HWND/TID/generation commit is rejected. Successful phase
  application advances both caret and rearmed deadline generations atomically;
  replay cannot toggle twice, and off phase retains the next deadline. Hidden,
  cleared, replaced or destroyed carets reject an outstanding expiry.
- Repeated ShowCaret and a same-position SetCaretPos preserve an armed
  deadline while retagging it with the new caret generation; they do not
  silently stop blinking. Showing an off-phase caret arms a fresh deadline.
- GetMessage timed waiting uses the minimum of the queue's caret deadline and
  the due time of its existing canonical WindowTimer entries. This is a
  read-only view of the existing timer owner, not a second timer registry.
  With neither deadline present the retrieval wait is unbounded; missing
  deadline is never encoded as an immediate timeout.
- Raw NtUserGetCaretBlinkTime (0x13d5, zero arguments) returns the canonical
  USER_SETTINGS caret interval in milliseconds. Raw NtUserSetCaretBlinkTime
  (0x153b, one UINT argument) stores that setting and returns Win32 BOOL 1;
  the current queue's future arm interval is updated only after the settings
  owner is released, and an already-derived deadline is unchanged.
- Raw NtUserGetCaretPos (0x13d6, one POINT pointer) reads the current queue's
  canonical caret position and returns Win32 BOOL. No caret, non-canonical
  current state, invalid pointer or failed bounded eight-byte POINT copyout
  returns 0 and cannot publish or mutate caret state; successful copyout
  returns 1. The adapter has no HWND input and cannot use an invalid HWND as
  a substitute for current-queue lookup.
- Uniform null-bitmap carets use the requested positive dimensions; zero width
  or height selects one border pixel. Their canonical mask is RGB inversion.
  Client-to-frame coordinates subtract the window origin from stored client
  origin. A replacement carries old HWND separately so erase targets the old
  backing surface. Bitmap and gray-pattern carets require their actual masks;
  no uniform-mask substitution is permitted for those requests.

- A missing or non-canonical HWND is rejected before state access.
- Text input is copied until its required UTF-16 terminator; unterminated
  input is rejected at the bounded service limit.
- Parentage and text remain in the native `WindowManager`; no adapter shadow
  table is permitted.
- Zero normal-window width/height is valid; reversed, overflowing or transport-unrepresentable extents are rejected before geometry/visibility changes.

## 3

- Hosted IPC and user32 tests cover text lifecycle, parentage, client geometry,
  visibility transitions, selector values, and buffer boundaries.
- The ordinary Windows compatibility gate and both kernel architecture builds
  cover integration.
- Placement tests cover the Notepad normal/default sequence, exact offsets, invalid length/pointer/HWND without mutation, unchanged coordinates across nonzero workarea origins, zero extents and FALSE on show/publication failure.
- Position tests exercise seventh-argument flags, move-only/size-only preservation, zero/negative sizes, visibility normalization, sibling rejection/no-op ordering, insertion sentinels, activation ordering and canonical child geometry/visibility. Dropping flags must fail these tests.

## 4

- UpdateWindow synchronously dispatches WM_PAINT for existing canonical client damage through the resumable Send owner in §1; it does not enqueue an application message or consume damage. BeginPaint remains the damage-consumption owner.
- Pending-paint traversal starts at the root, then visits descendants depth-first in topmost-first canonical sibling order. Each continuation re-reads current parentage, visibility and damage; no cached HWND list or second paint registry.
- Hidden windows or ancestors exclude painting. Minimized parents exclude descendant traversal. RDW_NOCHILDREN (0x40) excludes descendants and wins over RDW_ALLCHILDREN (0x80); ALLCHILDREN otherwise bypasses WS_CLIPCHILDREN, while default traversal requires WS_CLIPCHILDREN at each descent.
- The scan cursor is the last dispatched HWND, advanced before calling Send; an unchanged dirty region cannot immediately redispatch that HWND. A destroyed cursor ends traversal; a cursor outside the root subtree is invalid. Missing root HWND fails.
- Synchronous redraw state belongs to the process GUI entry: at most 64 nested scans, monotonic non-reused tokens, sender TID ownership, root HWND and previous cursor. No GUI/GDI lock crosses Send or callback execution. Immediate successful LRESULT, including zero, continues scanning; suspended Send resumes the same scan on its sender. Cancellation or failed delivery returns FALSE; completed traversal returns TRUE.
- Thread teardown cancels that sender's scans; root destruction cancels matching scans; process teardown drops all scans. A stale or foreign-thread token cannot advance or complete another scan. Nested UpdateWindow preserves the outer continuation.
- Current entry admits canonical nonzero full-width HWND, canonical HRGN snapshot, copied/ordered RECT or whole-window coverage, §5 damage mutations and optional UPDATENOW/ERASENOW. HRGN snapshot precedes GUI mutation and suppresses RECT access. Desktop-wide HWND-zero execution remains an integration gap. Unknown flag bits do not independently mutate state; UPDATENOW wins over ERASENOW.
- Hosted checks execute the actual redraw continuation against canonical window/paint state: root/child completion, immediate zero LRESULT, failed/cancelled delivery, nested callbacks, visibility/minimization/child flags, destroyed cursors, and unchanged damage. Replacing callback resume with unconditional TRUE must fail completion/cancellation tests.

## 5

- Canonical pending damage owns an exact region of nonempty, pairwise-disjoint, half-open rectangles plus independent internal-paint, erase, delayed-erase and nonclient state. Region union/intersection/subtraction preserve holes; bounding rectangles are output summaries, never validation or clipping substitutes. Allocation/coordinate failure returns an error without replacing the prior region.
- Each exact region admits at most 4096 rectangles; fragmentation/allocation exhaustion fails with no bounding-box fallback. The bound applies to intermediate subtraction fragments as well as committed coverage.
- RedrawWindow copies RECT or snapshots a canonical HRGN before mutation; HRGN takes precedence over RECT. RECT endpoints are ordered; empty input is a successful no-area operation. Null region means the entire applicable window area. Invalid handles and failed copies cannot mutate paint state.
- INVALIDATE takes precedence over VALIDATE; FRAME extends invalidation to nonclient bounds and ERASE requests background erasure. VALIDATE subtracts exact clipped coverage; NOFRAME additionally validates nonclient coverage and NOERASE clears erase/delayed-erase state when an update region exists. INTERNALPAINT takes precedence over NOINTERNALPAINT and can request WM_PAINT without damage.
- Invalidation/validation descends visible children unless NOCHILDREN, minimization or default WS_CLIPCHILDREN prevents descent; ALLCHILDREN overrides WS_CLIPCHILDREN. This descent differs from synchronous paint traversal in §4. Child coverage is intersected with parent client coverage, translated into child coordinates and DPI-mapped by the canonical geometry owner; inherited invalidation requests FRAME and ERASE. No fixed geometry or unchecked coordinate arithmetic.
- Message readiness derives from canonical pending damage/internal-paint state, not stale application-queue WM_PAINT copies. BeginPaint transfers the exact admitted client region into the active HWND paint session, consumes internal-paint state and preserves later invalidations for a subsequent paint. EndPaint consumes only that active session. HWND destruction removes pending and active state together.
- Paint retrieval selects a visible root before its children in topmost-first order; hidden/minimized ancestors exclude descendants. Transparent candidates yield to a lower nontransparent dirty sibling on the same thread. HWND filtering applies after candidate selection, so a filtered-out parent cannot be bypassed to paint its child. Returning WM_PAINT clears internal-paint state even for Peek; damage remains until validation/BeginPaint.
- BeginPaint and ERASENOW execute required WM_NCPAINT before WM_ERASEBKGND through the existing synchronous Send continuation. Erasure uses a real window HDC with exact update-region clipping; an empty clip suppresses WM_ERASEBKGND. Nonzero erase LRESULT clears the erase requirement; zero retains delayed erasure. PAINTSTRUCT.fErase reports the remaining requirement. HDC/HRGN cleanup occurs on completion, cancellation and failed installation outside GUI/GDI locks.
- BeginPaint preparation retains its original TID, HWND, bound HDC, PAINTSTRUCT destination and owned nonclient HRGN in the existing paint-callback completion payload, never a second callback registry. Final completion revalidates the canonical HDC/session before usercopy; successful completion transfers HDC lifetime to EndPaint. Failure drops only that admitted session and releases preparation resources, preserving newly pending damage. Queue teardown drains resource payloads before process memory/GDI detachment without resuming retiring user code.
- Foreign HWND destruction marks in-flight preparation canceled; its fresh HDC/HRGN remain leased until the outstanding Send returns, then cleanup executes without another paint callback or successful milestone. Quiescent preparation payloads drain immediately outside GUI ownership. Partial nonclient coverage uses an owned screen-coordinate HRGN; whole-window sentinel one requires exact coverage proof, not matching bounding boxes.
- UPDATENOW takes precedence over ERASENOW and sends WM_PAINT; BeginPaint owns its nonclient/erase preparation. ERASENOW does not consume client paint damage. Desktop-wide HWND-zero execution uses the canonical desktop/window hierarchy; no synthetic desktop identity. Flag-zero requests do not fabricate mutation.
- ERASENOW acquires canonical window backing before allocating/seeding a fresh clipped erase HDC, including before first BeginPaint. The sender owns the preparation; same-process cross-thread Send executes on the HWND owner. Completion compares current geometry before merging exact pixels, preserves later damage and releases owned HDC/HRGNs. Same-process teardown may dispose prepared resources from another TID without resuming the sender. Immediate completion drives the existing scan iteratively, not through recursive callback chaining.
- Active paint HDC clipping and presentation consume exact session coverage; rcPaint and legacy rectangular query APIs expose only its bounding box. New damage during callbacks cannot be erased by committing an old snapshot. Callback state is bounded, token/TID-owned and revalidated after every return per §4.
- BeginPaint subtracts consumed child coverage from ancestor update regions unless that ancestor clips children, translating through canonical client origins. All fallible region preparation precedes session/ancestor mutation.
- Tests cover disjoint unions, hole subtraction, empty/intersected/overflowing regions, combined-flag precedence, internal-only paint, validate/erase transitions, child-coordinate clipping, callback re-invalidation, actual clipped raster effects and cancellation resource cleanup. Replacing subtraction or clipping with a bounding box must fail.

## 6

- Desktop and WindowStation are typed objects in the existing NT object namespace (`31f`). Desktop payload retains its canonical station object; namespace publication validates that exact parent object, not an equal numeric ID. Reopening a name preserves object identity. No desktop-name registry beside the object namespace.
- Thread desktop membership retains the canonical Desktop object; process bootstrap supplies a distinct process-default reference through the same object owner. Initial membership is absent until an authorized bootstrap binds it. A station mismatch fails before mutation; switching to another desktop while the thread has canonical desktop users fails busy. Selecting the same object remains legal while busy. Child initialization inherits the process default, not the creating thread's selected desktop; it never replaces an already-selected child membership. A thread switch does not change the process default. No desktop/window state is copied.
- Desktop retains one nonzero, generation-validated root identity in the shared canonical window owner. The root belongs to the desktop, not an application process lifetime; owner-thread exit detaches thread resources without destroying the logical root. Desktop destruction removes that root. Publishing a different live root fails; identical publication is idempotent. Stale generations never resolve through reused HWND/PID values. Root publication follows canonical window creation; no fabricated root geometry, visible replacement shell or second window record. A weak application-process reference alone cannot represent this lifetime.
- HWND-zero RedrawWindow/GetDC resolve through current thread membership and this root; absent membership/root is an error, never a process-local window sweep. Root geometry and backing come from the existing GUI/GDI/compositor owners. Desktop UPDATENOW performs auxiliary desktop erasure before descendant WM_PAINT; it does not send WM_PAINT to the desktop itself.
- Cross-process traversal requires desktop-scoped canonical window identity and recipient-process callback/resource preparation. Sender-local HDC/HRGN numbers cannot be passed as recipient-local objects. Bootstrap object publication, thread/process attachment, root lifetime and shared hierarchy integration must precede admitting desktop-wide success.
- Trusted bootstrap creates/reopens station and desktop names only under the supplied canonical namespace parent, allocates process handles with caller-authorized rights, and attaches the resulting references before window creation. It does not guess a session from DISPLAY/PID/monitor equality. Failed attachment closes admitted handles; process-table teardown releases committed handles. Reopening from another process preserves the same station/desktop/root identity.
- Process-parameter Desktop is a userspace name-selection input, not a capability or authorization grant. Name resolution/create/open must enforce canonical namespace authority before allocating handles. Selecting an existing desktop resolves a typed handle in the caller's process table, validates exact process-station identity before busy state, and does not amplify its granted access. Initial-thread inheritance supplies canonical references through the same owner.
- Bound desktop preparation consumes selected canonical process-station/thread-desktop references plus the existing real monitor snapshot; it accepts no station name or requested access mask and creates no objects. Missing membership fails before monitor lookup. A geometry-only compositor binding cannot authorize station creation or infer session identity. Public bootstrap ingress must transfer authorized canonical handles or perform access-checked namespace operations; no numeric selector is assigned by this internal contract.
- Initial bootstrap publishes the process-default desktop once together with initial-thread membership. Conflicting prior default is rejected before any mutation; identical bootstrap preserves it. Later thread selection changes only that thread. Default publication fills unassigned thread memberships, preserving explicitly selected ones; the initial single-thread bootstrap has only its current thread to fill. Same-process child creation snapshots the process default before callbacks/runnable publication with no nested process/thread locks.
- NtBindDesktop tagged bootstrap service takes station handle in a0 and desktop handle in a1, each an exact zero-extended canonical 32-bit process-local handle; no pointer/string/session ID or requested access mask. Both handles must resolve with their correct object types and the desktop must retain that exact station. It runs on the single initial thread before GUI users exist, permits identical rebind, rejects replacing prior membership, and attaches retained canonical references without creating objects or handles. Invalid encoding returns INVALID_PARAMETER, missing/stale handles INVALID_HANDLE, wrong types OBJECT_TYPE_MISMATCH, mismatched station ACCESS_DENIED, conflicting or non-initial attachment DEVICE_BUSY; success is NTSTATUS zero. The integration owner assigns the tagged selector. Session bootstrap must supply already-authorized handles; the compositor fd alone is insufficient. Root publication and monitor acquisition remain separate operations.
