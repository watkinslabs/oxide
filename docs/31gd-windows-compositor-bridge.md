# Native Windows compositor bridge

Status: FROZEN
Date: 2026-09-06
Depends on: 25, 31ab, 31fj, 31fk, 31fl, 52, 53

## Contract

Native Windows GUI applications must appear as ordinary desktop-managed windows.
GNOME, KDE and JWM are supported desktop/window-manager targets; NT semantics
must not depend on a particular desktop shell. The X11 backend uses the active
X server, including a desktop's XWayland server. Native Wayland requires its
own protocol backend; XWayland acceptance does not establish native Wayland
support. GNOME remains the initial integrated Notepad acceptance environment. It
uses the session DISPLAY and authorization, never a private desktop or direct
scanout overlay. Linux socket and graphics facilities provide transport and
presentation; the kernel's existing USER32/GDI owners retain Windows semantics.

The launcher supplies a connected AF_UNIX stream endpoint capability to the
native process. Binding validates the endpoint and associates it with the
canonical ThreadGroup. No global writable rendezvous or guessed process IDs
authenticate clients. Endpoints and workers terminate with process teardown.

## Ownership and protocol

The syscall shared crate owns a versioned, little-endian framed protocol.
Every header, opcode, payload length, dimension, stride, coordinate and pixel
extent is checked before allocation or access. Explicit finite frame and queue
limits apply to both userspace and kernel, including socket buffering. Partial
reads/writes, interruption, malformed input and EOF are normal error paths.
Backpressure must not silently acknowledge an unpresented frame as success.

The syscalls compositor module owns transport lifetime, bounded immutable
outbound records, monitor snapshots and event delivery through the existing GUI
owner. No GUI, GDI or scheduler spinlock may be held across socket I/O. The
initial protocol may carry owned pixel bytes; it never transports raw kernel or
userspace pointers. Later shared-buffer optimization is not required for this
first correct path. Pixel format and row layout are explicit on the wire.

The userspace windows-compositor owns only HWND-to-XID presentation mappings,
X11 connections, images and event translation. It does not duplicate class,
window procedure, message queue, focus or Windows object ownership semantics.
Window geometry permits zero width/height: Notepad creates its status-bar child
as 0x0 before layout (Wine programs/notepad/main.c). Monitor workareas and pixel
frames still require positive extents. X11 storage may need a private minimum
1x1 backing window, but a logically zero-sized HWND remains unmapped and must
not report that backing size as its Windows geometry. Child HWNDs use their
parent XID; owned top-level popups use transient ownership instead of parenting.
Creation, visibility, title, geometry, pixels and destruction flow from the
canonical kernel window owner. Configure, keyboard/text, pointer and close
events return to that owner. A WM_DELETE_WINDOW request becomes a Windows close
request, not an unconditional process kill. Stale handles/events are rejected.

## Caret presentation

Caret presentation uses outbound opcode 8: generation u64, window-frame Rect
(16 bytes), visible u32 (0/1), format u32 (1=RGB-XOR), followed by tightly packed
little-endian u32 RGB masks only when visible. Generation is nonzero; visible
rectangles are positive, masks have zero upper byte, and mask storage is bounded
to 256 KiB. Hidden records contain no mask. No pointers or bitmap handles cross
the wire. The canonical GDI/caret owner resolves bitmap pixels, client mapping,
visibility and blink phase; each phase publishes a snapshot outside GUI locks.

The backend retains only a presentation snapshot per existing HWND/XID mapping.
It composites RGB XOR against pristine window pixels for every repaint/frame,
preserving alpha and row padding. Hide/move restores the old footprint from
those pristine pixels. Older generations are ignored; equal-generation ordered
erase/paint updates remain valid. Destruction removes the presentation snapshot.
No backend caret timer or duplicate Windows hide-depth/focus state exists.
Caret ACK acknowledges accepted presentation configuration; when no base frame
exists it remains pending until that frame arrives, never fabricates background
pixels, and does not count as a presented-frame milestone.

## Desktop focus

Focus events use backend opcode `0x108`, nonzero canonical top-level HWND,
and exactly one little-endian `u32 active` (`0` deactivate, `1` activate).
No raw X11 focus detail/mode values cross this boundary. Child XID focus maps
to its top-level HWND; internal ancestor/descendant focus changes do not imply
desktop deactivation. Unknown values and malformed lengths are rejected.

The canonical window owner stores active top-level and remembered descendant
focus. Activation preserves an existing descendant focus or restores a live
remembered descendant; otherwise it focuses the top-level window. Deactivation
clears current focus and preserves the descendant for later activation. Stale
deactivation for a different active top-level is an accepted no-op. Destruction
clears active/remembered references. Activation emits WM_NCACTIVATE/WM_ACTIVATE;
activation-thread changes emit WM_ACTIVATEAPP to those threads' top-level
windows, with the known peer thread ID (zero for an external desktop peer);
focus changes emit
WM_KILLFOCUS/WM_SETFOCUS. Queue capacity for every affected owner thread is
checked before state or messages mutate. Duplicate focus records are idempotent.
GUI wakeups occur after unlocking; focus never kills the process or disconnects
a healthy bridge merely because the event is unsupported by an old path.

## Desktop geometry

The backend reports actual connected-screen/monitor geometry and the current
desktop's EWMH _NET_WORKAREA, observing changes to desktop and workarea
properties. These snapshots feed native default placement and screen metrics.
Missing, malformed or disconnected desktop data is unavailable, not a fabricated
fixed rectangle. A snapshot is scoped to its bound desktop connection.

## Launcher and image

The ordinary make qemu-x86 image includes the bridge, its dynamic dependencies,
Notepad and the existing Windows runtime/catalog. The normal desktop launcher
starts the bridge in the user's active graphical session and hands the endpoint to the
runtime before executing the PE. Failure identifies the missing bridge/session
dependency instead of claiming a successful window. No separate manual image
assembly is required to test Notepad.

Image assembly finishes with a read-only payload gate: required launcher/bridge,
PE32+ AMD64 Notepad, native ELF64 AMD64 pair, defined native thread-attach export,
catalog links and desktop/MIME launch targets. Native pair bytes must match the
selected staging inputs; file presence or timestamps do not establish provenance.
Any gate failure fails assembly before reporting the image ready.

## Verification

Position opcode 7 carries 16 bytes: insertion HWND u64, flags u32, reserved
u32=0. Flag 1 supplies insertion ordering, flag 2 requests activation; no other
bits are valid. Without ordering, insertion is zero. Insertion values 0/1/-1/-2
mean top/bottom/topmost/not-topmost; other values identify a canonical sibling.
Kernel commits canonical ordering before sending; backend resolves only mapped
XIDs and applies X11 sibling order or EWMH top-level state/activation.
Acknowledgement means request submission succeeded, not that the window manager
granted focus. Actual focus remains an incoming Focus event.

Hosted protocol tests cover malformed headers, unknown versions/opcodes, length
and pixel overflow, fragmented records, bounded queues, EOF and disconnect.
Transport and GUI tests exercise actual production integration hooks, process
ownership and cancellation; negative controls demonstrate rejected inputs.
Backend tests cover window mapping, title, frame conversion and event decoding.
Both kernel architectures must compile. The integrated acceptance gate requires
a real GNOME-managed Notepad window, visible text entered through desktop input,
normal close and clean exit. Unit tests or a raw framebuffer rectangle do not
substitute for that acceptance result. No boot is needed before implementation
and nonboot gates are ready.

Native acceptance requires an observed desktop frame acknowledgement in
addition to PE entry, native attachment, creation, message/paint activity and
the screenshot/input/exit checks. Wine server entry remains evidence for the
Wine-server path, not a prerequisite for the native compositor path. Creation
callbacks can paint synchronously, so event observation must not suppress a
valid paint solely because the message-loop or creation-completion marker has
not yet occurred.

## Reference basis

Local Wine win32u window/message behavior, Linux AF_UNIX socket lifetime and
backpressure, and installed XCB xcb.h/xproto.h APIs provide the implementation
reference. EWMH desktop properties and X11 WM_PROTOCOLS govern the backend,
without extending those properties into invented Windows semantics.
