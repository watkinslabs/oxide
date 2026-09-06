# Windows GDI client state

FROZEN 2026-09-06. Dep:`31fk`,`31fj`,`31n`,`52`,`53`.

## 1

- Canonical process GDI owner allocates identities, owns selected objects and pixels, and destroys objects. Client handle entries are an ABI projection, never an allocation authority or object registry.
- USER32 client-PFN initialization binds the client table before publishing successful initialization. Native Unixlib table registration does not initialize GDI objects. A nonzero foreign PEB table is an ownership conflict, not a table to overwrite or import.
- Binding publishes the owned table at the 64-bit PEB GdiSharedHandleTable offset 0xf8. No native object pointer or kernel address enters client memory.
- Table has 65536 entries, each 24 bytes. Per-slot DC attributes use the matching client ABI stride in a separate bounded anonymous user mapping. Canonical process state retains mapping identity and address; pointer arithmetic is checked.
- Slots and unique/type words derive from `31fk` canonical handles. Fixed stock identities derive from the canonical stock-object owner. Unknown/deleted slots have Type=0. Publication prepares attributes before making the handle entry live.
- A failed mapping or usercopy cannot return a successful newly published handle. Allocation rollback removes the object; deletion clears the projection. Final address-space destruction reclaims mappings.
- User modifications to entry Object, Type, Unique or UserPointer cannot create kernel objects, redirect kernel attribute access, or select another process's object. Kernel resolves identities against its owner and computes attribute addresses from its retained mapping and canonical slot.

## 2

- Bound DC attributes are shared state, not a cached duplicate of private TextAttributes. PE direct writes are observed by later kernel drawing operations; private facade DCs retain private attributes only when no client binding exists.
- Text snapshot copies and validates the shared record before a render/measure callback. Invalid modes, dimensions, pointer arithmetic or usercopy fail before drawing. Client COLORREF colors convert to canonical XRGB at this boundary.
- Own/class and NORESETATTRS release do not republish private defaults. Ordinary cached release explicitly reinitializes shared attributes under the existing lifetime gate.
- Setters update the shared field when bound and private state when unbound; they never update one while consumers read the other. Selected font and pixel ownership remain canonical kernel data.
- Direct client fields include current position, text alignment and background mode. Client-visible colors and geometry reflect successful canonical changes. Unsupported attribute semantics fail explicitly rather than being silently reset.
- Empty nonnegative visible extents do not invalidate HDC metadata or font queries. Encoding/decoding accepts zero area; reversed or overflowing signed extents remain invalid. Pixel/frame admission separately requires actual drawable coverage. Geometry-only publication validates mapping and HDC identity, writes only extent fields, and does not reject unrelated render attributes or reset preserved shared bytes.
- Mapping allocation and usercopy occur outside GDI/GUI spinlocks. Canonical lifetime checks and immutable mapping snapshots occur under the owner lock; no borrowed owner record crosses a sleeping operation.
- Publication and teardown serialize against object lifetime; concurrent failed publication cannot resurrect a deleted slot. Stale handles never alias a later dynamic object.

## 3

- ABI fixtures pin 24-byte handle entries and the exact client DC_ATTR layout, including Unique/type/stock bits and UserPointer.
- Hosted tests exercise client handle admission against projected canonical DC/font identities, direct attribute writes followed by snapshots, deletion, foreign-table rejection and failed-copy rollback.
- Empty-DC fixtures cover exact (0,0), (0,n) and (n,0) metadata through first handle publication, text snapshot, canonical font metrics and cached reset; malformed extents and unrelated invalid render attributes remain negative controls.
- Positive controls remove type bits, client publication or shared-state reads and must fail the corresponding checks.
- Both architecture builds compile binding and access paths. A successful hosted projection does not establish desktop Notepad acceptance.
