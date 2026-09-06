# Windows GDI text foundation

FROZEN 2026-09-06. Dep:`01`,`02`,`29a`,`31h`,`31fj`,`52`,`53`.

`windows-gdi` owns the Win32-facing text façade. Native NT process state owns
device contexts and logical fonts; Linux display drivers remain the display
owner. The adapter does not maintain a second GDI object table.

## 1

- `CreateCompatibleDC` creates a positive-dimension memory device context.
- `CreateFontIndirectW` creates a fixed 64-bit logical-font record containing
  height, width, weight, and italic state.
- `SelectObject` selects a font into a device context and returns the previous
  font handle.
- Raw NtGdiGetDCObject 0x11f0 takes HDC and internal object-type bits, not
  public OBJ_* indices. Font/brush queries return the DC's actual selected
  canonical identity, including pending-deletion selections; invalid DC or
  unrepresented selection returns NULL without allocating an object.
- Immutable stock font/brush/pen metadata belongs to the same GDI owner; fixed
  handles encode slot 32+stock index, actual object type and stock bit 0x00800000.
  Public supported indices are 0..8, 10..14 and 16..19. Palette/bitmap and private
  scaled-font indices are not fabricated. DC_BRUSH/DC_PEN descriptions identify
  DC-controlled color, distinct from immutable initial white/black values.
- ANSI stock font logical (height,width,weight) values are OEM_FIXED/ANSI_FIXED
  (12,0,400), ANSI_VAR (12,0,400), SYSTEM (16,7,700), DEVICE_DEFAULT (16,0,700),
  SYSTEM_FIXED (16,0,400), DEFAULT_GUI (-11,0,400); all non-italic. Logical face,
  charset and pitch metadata remain immutable; native resource substitution
  follows `31ge§2`, never rewriting SYSTEM width 7 to zero.
- New DCs select SYSTEM_FONT. Deleting a valid stock object returns success
  without removing it or changing selections; forged stock/type/slot combinations
  fail lookup. Stock metadata requires no mutable process registry or allocation.
- `GetTextMetricsW` reports height, ascent, descent, average width, maximum
  width, and character width from the selected font or stock font.
- `GetTextExtentPoint32W` measures UTF-16 code units without taking ownership
  of the caller buffer.
- Each memory device context owns a bounded row-major XRGB pixel surface.
- Reacquiring a window DC after a geometry change resizes that same DC,
  retaining its handle, selected font, text attributes and overlapping pixels.
  Invalid dimensions leave the old DC intact.
- The same DC owns text foreground/background colors, background mode,
  alignment and current position. Defaults are black text, white background,
  opaque mode, left/top alignment and origin (0,0). Font/text-state snapshots
  are copied from this owner before a userspace raster callback; a renderer
  never maintains a second mutable HDC attribute table.
- `FillRect` clips to that surface before writing pixels.
- Each canonical DC retains optional application clip geometry, independent
  of surface size. IntersectClipRect normalizes endpoints and intersects the
  retained clip; first successful clip installation returns SIMPLEREGION even
  when empty, while subsequent empty intersections return NULLREGION.
- Each DC separately retains optional paint clip geometry. Fresh BeginPaint
  DCs receive the admitted update rectangle before paint callbacks/return;
  this never overwrites application clip or changes its intersection history.
  Reversed paint bounds fail without mutation; zero-area paint bounds are empty.
  Effective drawing/query clip is surface intersected with application and
  paint clips. DC deletion releases paint geometry; resize preserves both
  retained clips. No paint-DC reuse or stable GetDC lease reset is implied.
- Paint clips retain the admitted canonical disjoint rectangle region, not its
  bounding box. None means no paint restriction; an empty region clips all
  drawing. Raster membership intersects the exact region with surface and
  application bounds. Clip-box queries return the bounding rectangle plus
  NULL/SIMPLE/COMPLEX complexity of effective coverage; holes remain undrawable.
  Region replacement transfers an owned canonical snapshot without another
  region registry; malformed rectangle convenience input fails before mutation.
- GetAppClipBox intersects application and paint clips with visible surface bounds,
  writes the complete RECT, and returns region complexity; empty output is
  four zero coordinates. Invalid DC or failed output copy returns ERROR=0.
- Fill, pattern blit, destination bitblt, uploaded raster and alpha/glyph blend
  honor the same effective DC clip. Source clipping does not constrain a
  BitBlt source. Resizing retains application clip and recomputes visible bounds.
- Raw IntersectClipRect is ordinal 0x1238 with five arguments; GetAppClipBox
  is 0x11db with two. Owner snapshots precede output usercopy outside GDI locks.
- Userspace may upload a validated row-major XRGB raster into a DC; the native
  owner clips the upload before writing the surface.
- Userspace rasterizes TrueType/OpenType glyphs, including UTF-16 surrogate
  decoding and glyph advances, before uploading an XRGB text tile.
- Transparent text retains userspace glyph alpha; canonical DC upload blends
  ARGB coverage over existing pixels instead of painting the background color.
- `ExtTextOutW` performs optional opaque background fill, optional rectangle
  clipping, per-code-unit advances, and native tile submission in userspace.
- Raw text ingress preserves GLYPH_INDEX, IGNORELANGUAGE and PDY through the
  existing native callback; glyph-index WORDs bypass character lookup and PDY
  consumes two signed advance values per WORD. Only OPAQUE/CLIPPED request a
  rectangle read. Text/advance extents are checked before callback admission.
- PE raw text output reaches the same userspace renderer through the bounded
  same-task callback contract in `31ge§1`; no kernel rasterizer or second DC owner.
- A native `PresentGdiSurface` submission copies a DC into the primary scanout;
  the display driver owns scanout clipping and transfer/flush ordering.
- `PresentGdiWindow` resolves the canonical HWND and sends an owned DC frame
  through `31gd`; desktop acknowledgement completes the submission. Hidden
  windows may paint retained backing before mapping.
- `EndPaint` submits only the consumed dirty client rectangle through the same
  window/DC/display owners; non-paint presentation retains whole-surface
  semantics.
- Raw `BeginPaint` validates the canonical HWND before allocating or binding a
  paint DC; zero/unknown HWND returns NULL and never selects a default surface.
  A NULL `PAINTSTRUCT` still runs native paint preparation and releases its
  temporary paint resources before returning NULL. Failed preparation cleans
  every acquired canonical resource in reverse ownership order.
- Raw paint reserves canonical damage without preliminary PAINTSTRUCT copyout;
  nonclient/background callbacks finish before terminal output validation/copy.
  NULL output still completes callbacks, then releases the temporary HDC and
  active session without writing user memory or publishing a BeginPaint milestone.
  Callback drawing survives that release in canonical backing; empty coverage
  produces no frame. Retention/transport runs outside GUI ownership.
- Paint retention merges only admitted client damage from the temporary paint
  DC into the existing canonical window DC, translating by the canonical
  window-relative client origin. The caller supplies copied outer dimensions
  and client bounds; no GDI-side geometry registry is introduced. Source paint
  pixels remain client-origin even when their allocated surface is window-sized.
- Before paint admission/drawing, the temporary DC receives retained client
  pixels translated from the canonical window-relative client origin to (0,0).
  Seeding copies only the client extent, preserves all DC attributes and pixels
  outside that extent, and ignores storage-copy source/destination drawing clips.
  Missing, aliased or dimensionally inconsistent DCs fail before mutation;
  seeding neither allocates nor resizes. This preserves underlying pixels for
  transparent drawing and application-clipped portions of admitted damage.
- Retention preserves destination pixels outside damage and all destination DC
  attributes. Storage merging ignores destination application/paint clipping;
  drawing into the paint DC already consumed those clips. Validation and any
  checked resize allocation precede mutation. Missing backing fails without
  creating an unpublished DC. Presentation snapshots the retained window DC
  after merging and submits only after dropping GUI/GDI locks.
- Exact paint retention validates every admitted region rectangle against
  client/source bounds before resizing or writing. It performs one checked
  resize and copies only disjoint coverage, never the enclosing box. Invalid
  later rectangles cannot leave earlier rectangles merged or backing resized.
- Dynamic fonts retain all 92 LOGFONTW bytes in their canonical object record;
  logical measurement attributes derive from that record. Stock descriptions
  serialize through the same query contract, without a parallel font registry.
- Deleting a selected dynamic font marks it pending deletion. Selections,
  identity and client projection survive until the final DC releases it;
  deselection and DC destruction collect pending objects. Stock deletion
  remains successful and immutable.
- Raw NtGdiExtGetObjectW ordinal 0x11c7 takes handle, signed count and output
  pointer. Null output queries size irrespective of count; non-null output
  copies a prefix capped at object size, with negative count selecting full
  size. Unknown/finally collected identities return zero; pending selected
  objects remain queryable. Non-null destination below
  0x10000 fails with ERROR_NOACCESS. Canonical snapshots precede usercopy,
  which runs outside GDI locks under the object lifetime gate.
- Tagged NT selectors carry the ABI; Linux syscall numbers are not used for
  Windows behavior.

### Raw win32u ingress

The x86-64 raw win32u adapter claims the bounded Notepad text path and only
decodes it into the canonical GDI owner: `NtGdiCreateCompatibleDC`,
`NtGdiDeleteObjectApp`, `NtGdiHfontCreate`, `NtGdiSelectFont`,
`NtGdiGetTextMetricsW`, `NtGdiGetTextExtentExW`, and
`NtGdiExtTextOutW` (ordinal `0x11c9`, all nine arguments). The adapter owns no
GDI table, does not rasterize, and never returns a fabricated success value.
The native owner supplies the RasterFont callback and performs the bounded
user-buffer validation, clipping, opaque fill, and tile submission described
above.

## 2

- Handles are process-local and invalid after deletion.
- GDI handle identity uses a 16-bit slot and object type in bits 16..22;
  DC type is 1 and font type is 10. Slots below 64 are reserved for fixed
  client/stock identities. Dynamic slots start at 64 and never wrap or alias
  a deleted object; exhausting the 16-bit slot namespace fails allocation.
- Dimensions and font values reject integer-minimum overflow inputs.
- Text buffers are copied and validated before the extent result is written.
- Surface dimensions are bounded before allocation; rectangle writes never
  address pixels outside the owning device context.
- Raster tiles have an independent pixel bound; invalid font bytes, non-finite
  sizes, invalid dimensions, and short source buffers fail before upload.
- Empty text does not upload pixels; opaque empty text still fills its requested
  rectangle.
- Presentation rejects absent/quiesced scanouts and never writes outside the
  driver-owned framebuffer backing.
- Zero-sized, unknown, or cross-process HWND/DC combinations do not submit
  frames; hidden backing updates never imply desktop visibility.
- The desktop compositor owns native window presentation; GDI owns the raster
  surface and its drawing operations. Direct surface scanout remains separate.
- A paint submission with an empty, malformed, or out-of-surface region fails
  before the display owner is called.

## 3

- Hosted GDI tests validate object lifecycle, selection, metrics, extent, ABI
  layouts, and selector values.
- Native IPC tests validate the same owner rules.
- The normal `windows-compat-test` suite and both kernel architecture builds
  cover integration.

## 7

- GetDCEx returns a canonical lease HDC or NULL, never an NTSTATUS-shaped
  handle. Lease records occupy the existing DC owner and reference the existing
  window backing without allocating a second pixel surface. Client leases map
  logical (0,0) to the canonical client origin; window leases map to window origin.
- Zero window width or height retains exact canonical dimensions and a valid
  DC for attribute/font queries with empty pixel storage. Negative dimensions
  remain invalid; no synthetic backing pixel or positive frame is submitted.
- First shared DC_ATTR publication and metadata decoding admit zero extents;
  visible-rectangle subtraction remains checked and reversed extents fail.
  Identity, disabled-state, transform and text-attribute validation order remains
  unchanged. Positive raster/frame payload admission is a separate boundary.
- WINDOW/PARENTCLIP force cached selection. USESTYLE derives child/sibling/parent
  clipping from canonical window/class styles. WINDOW suppresses child clipping;
  top-level leases suppress parent clipping and include sibling clipping. Exact
  visible coverage comes from canonical window geometry, not a guessed rectangle.
- Cached leases are distinct while active and reusable after release. Common
  DC attributes reset on release unless NORESETATTRS; own/class DC attributes
  persist. Release validates the active HDC, not a supplied HWND substitution,
  disables cached leases and leaves canonical backing pixels unchanged.
- Reused lease publication preserves the complete shared DC attributes, updating
  only visible geometry. Own/class and NORESETATTRS release never republish private
  defaults over shared attributes; ordinary cached release explicitly resets them.
- INTERSECTRGN/EXCLUDERGN consume canonical HRGN geometry; both flags select
  intersection. NULL region means empty coverage for intersection and no cut
  for exclusion. Ignored region arguments are neither validated nor consumed.
  Accepted region identities transfer to the DCE and are deleted on cached
  release or replacement; whole-window callback sentinel is resolved by the
  callback owner before ordinary region lookup.
- Consumed HRGN rectangles are screen coordinates. The copied geometry subtracts
  the canonical lease screen origin exactly once before logical intersection;
  overflow rejects admission before owner mutation. Original HRGN identity is
  retained for ownership/release, never replaced by a translated shadow handle.
  Backing HWND and backing HDC must match the existing canonical association,
  independently of the requesting child HWND used by parent-clipped leases.
- Raster paths resolve lease origin, exact visible region and backing storage
  through the same GDI owner. Application/paint clips remain per-HDC and cannot
  alter backing-wide attributes. Lease publication/reset and region projection
  cleanup run under the client lifetime gate, outside GDI locks for usercopy.
- Resizing a lease HDC is rejected; only its canonical backing may resize.
  Deleting a cached lease releases its consumed region and selections, never
  its backing. Application deletion of own/class DCEs returns success without
  deleting the identity, consumed region, selections or attributes. Backing
  deletion revokes every referencing lease before removing pixel storage;
  HWND teardown also revokes leases requested by that HWND against parent backing.
  Revocation removes identities from the existing owner, with projection cleanup
  derived from before/after live-handle snapshots outside the GDI lock.
- Pending rendered output belongs to the existing backing DC, separate from GUI
  invalidation. Each raster operation coalesces changed pixels into conservative
  backing-coordinate bounds without per-pixel allocation, then advances generation
  once. Read-only, unchanged, clipped and empty operations add no output.
  Snapshot tokens bind HWND, backing HDC and generation; only an acknowledged
  matching generation clears pending bounds. Newer output and failed submission
  remain pending. Generation saturation never permits a stale ACK to clear output.
  One canonical in-flight token serializes each backing's submissions; finishing
  an older token cannot release another reservation or consume newer output.
  Message-pump idle/non-idle and explicit presentation share this accounting;
  ReleaseDC is not the sole or required flush boundary.
- Explicit presentation requests full positive-sized backing output even when
  pixels are unchanged. Request advances the same generation without changing
  pixels or taking another reservation; an in-flight older frame cannot consume
  the new request. Wrong HWND/backing associations and zero dimensions fail
  before output mutation. Ordinary raster tracking remains change-only.
- NOREDRAW backing replacement advances generation without adding fresh output;
  existing pending bounds survive intersected with new backing extent. A clean
  backing remains clean. Redraw-enabled replacement requests the full new extent.
  Neither replacement releases an older in-flight reservation.

## 4

- Stock object identities occupy fixed slots beginning at 32 and carry the
  stock bit 0x00800000 plus their object type. Immutable stock descriptions
  belong to the canonical owner; deletion succeeds without removing them.
- Stock font logical dimensions, weight and italic state are retained through
  selection. Resource substitution follows `31ge`; nonzero logical width
  cannot be silently replaced by width zero.
- Solid and hollow brushes belong to the same object owner as fonts and DCs.
  Each DC owns its selected brush; selection returns the previous identity,
  validates object type/lifetime, and never changes another DC.
- Pattern blits evaluate the requested source-independent ternary raster
  operation against the canonical destination and selected brush. A raster
  operation requiring a source fails before mutation; clipped-empty work
  succeeds after DC validation. Signed extents preserve raster orientation.
- Raw brush colors convert COLORREF to canonical XRGB. Hollow-brush behavior,
  stock brush selection and deletion remain owner semantics, not adapter
  success shortcuts. Brush/DC mutation and presentation share the same pixels.
- Tests pin stock identity/type/immutability, independent DC selection,
  signed clipping, source-dependent rejection and pattern/destination truth
  tables. Removing raster evaluation or stock preservation must fail.

## 5

- Default control-color handling for EDIT/LISTBOX sets DC foreground to
  COLOR_WINDOWTEXT and background to COLOR_WINDOW, then returns the canonical
  COLOR_WINDOW brush. MSGBOX/BUTTON/DIALOG/STATIC use COLOR_3DFACE background
  and brush. DC background mode, alignment, selected brush and font remain
  unchanged. Scrollbar patterned-background handling is a distinct operation.
- Canonical initial system colors are XRGB WINDOW=0x00ffffff,
  WINDOWTEXT=0x00000000, 3DFACE=0x00d4d0c8, BTNSHADOW=0x00808080,
  BTNTEXT=0x00000000, BTNHIGHLIGHT=0x00ffffff, 3DDKSHADOW=0x00404040,
  3DLIGHT=0x00d4d0c8, SCROLLBAR=0x00d4d0c8. These are owner defaults, not a
  claim that desktop theme or SetSysColors updates are already integrated.
- System brushes are lazily allocated solid brushes in the existing process
  GDI owner and cached by color role there. They use real typed identities,
  participate in live-handle snapshots and normal client publication, and are
  protected from application deletion even when unselected. No second object
  registry, stock-brush substitution or per-message brush allocation.
- Default handling attempts both shared-aware DC color setters before brush
  lookup; failed DC setters do not suppress the returned system brush. Brush
  allocation/publication failure returns NULL. Successful handling never
  selects the brush into the DC on the caller's behalf.
- Client publication remains under the existing lifetime gate and outside
  GDI locks. A failed projection cannot expose an uninitialized client handle;
  a protected cached brush may be retained for a later publication retry.
- Tests select the returned brush and execute real pattern fills, inspect
  clipped pixels and DC attributes, and verify stable identity, deletion
  protection, unknown-role rejection and failed-publication NULL results.

## 6

- HRGN storage belongs to canonical GdiManager.regions, entries (typed handle, PaintRegion). Geometry uses existing exact disjoint PaintRegion coverage, including holes; no alternate region type or registry. TYPE_REGION=0x040000, existing monotonic dynamic slots >=64; integer 1 is never a region handle and remains only a caller-specific full-window sentinel.
- Creation transfers owned coverage; rectangular creation orders signed endpoints and permits empty regions with real handles. Fallible allocation/handle exhaustion exposes no identity. Region snapshot is an owned fallible copy, independent of later replacement/deletion; borrowed owner geometry never crosses usercopy or callbacks.
- Query returns NULLREGION=1 with zero bounds for empty, SIMPLEREGION=2 for exact rectangular coverage, COMPLEXREGION=3 otherwise. Adjacent disjoint rectangles covering their bounds classify simple; holes never collapse into simple coverage. Wide area arithmetic avoids overflow for full signed-coordinate spans. Invalid/type-forged/deleted/sentinel handles fail.
- Replacement consumes already-owned geometry only after handle validation. Deletion removes region immediately; paint/DC consumers retain explicit owned snapshots, not hidden references. Canonical contains/live-handle projections and generic DeleteObject include regions; handle slots never reuse deleted identities.
- Native creation shares existing process lifetime gate and publication/rollback transaction. Bound client publication uses the region's typed identity with no kernel pointer; failed publication removes both projection and canonical region. Query/copyout and client publication occur outside GDI locks. Native region deletion uses the same generic lifetime-gated object deletion, not a second teardown path.
- Hosted tests exercise actual canonical creation/query/replacement/deletion, projection liveness/type identity, empty/reversed/extreme rectangles, holed coverage, snapshot independence and allocation exhaustion. Bounding-box substitution and omitted generic deletion must fail controls.
- Raw CreateRectRgn=0x10bb has four signed DWORD coordinates and returns HRGN/NULL; GetRgnBox=0x121e has HRGN/output RECT and returns complexity/ERROR=0 after complete 16-byte copyout. CombineRgn=0x10a2 has destination, source1, source2, signed DWORD mode and returns resulting complexity/ERROR. Handles/pointers retain all 64 bits at decoding; canonical handles must fit u32, coordinates/mode truncate to low DWORD. Unknown ordinals remain unclaimed; recognized malformed calls return zero.
- Combine modes AND=1, OR=2, XOR=3, DIFF=4, COPY=5 reuse existing exact PaintRegion union/subtraction. Destination and source1 must be live; COPY ignores source2; other modes require source2. Sources snapshot before destination mutation, including aliases. Invalid modes/handles/resource failure preserve destination and identity. No bounding-box combine or synthetic region handle. GetRgnBox copies outside owner lock; invalid destination pointer/copy returns ERROR without changing region.

- SetRectRgn raw0x1287 takes HRGN plus four signed DWORD coordinates and returns BOOL, never complexity. Canonical region identity validates before geometry allocation, signed endpoints normalize independently, either zero extent clears coverage successfully. Replacement preserves handle/projection and existing consumer snapshots; invalid/type-forged/deleted/sentinel handles or resource failure preserve owner state. No replacement handle or client republishing. Hosted joined tests exercise raw truncation, exact canonical replacement, empty/reversed/extreme bounds and negative mutation controls.

## 8

- Canonical pens live in GdiManager.pens with TYPE_PEN=0x300000 and existing dynamic slots. DC selected pen defaults to BLACK_PEN; DC_PEN resolves that DC's pen color. Stock pens retain fixed identities. Dynamic selected deletion is pending until final deselection/DC teardown, reflected in generic live-handle/client projection lifecycle. No parallel pen registry.
- CreatePen raw0x10ba takes signed style/width, COLORREF, ignored brush argument; styles SOLID0/DASH1/DOT2/DASHDOT3/DASHDOTDOT4/NULL5/INSIDEFRAME6. NULL returns existing NULL_PEN regardless width/color. Other widths retain absolute logical width; integer-minimum rejected. Unsupported styles or unsupported palette colors fail NULL. SelectPen raw0x126f takes HDC/HPEN, validates canonical objects, returns previous pen or NULL without mutation on invalid input.
- LineTo raw0x123a takes HDC/signed endpoint; draws from current position excluding final endpoint, then updates position only on success. Rectangle raw0x1259 takes HDC/four signed edges; normalizes endpoints, excludes bottom/right boundaries, fills selected brush interior and strokes selected pen without changing current position. Empty rectangles succeed after DC validation; null pen suppresses outline, not fill. GM_COMPATIBLE/MM_TEXT semantics; other transformations need their actual owner.
- Required cosmetic width0/1 coverage uses direction-biased integer lines, rectangle corner pixels once, and existing source/ROP2 pixel operation through canonical DcPixel mapping. Raster never indexes private DC pixel vectors, bypasses lease origin/visible/paint/application clips, or owns another pixel store. Solid/null required paths precede broader wide-pen geometry; unsupported stroke modes fail before mutation, never draw an invented solid substitute.
- Hosted tests pin stock/null/typed pen identity, pending-delete selections across multiple DCs, canonical projection, line endpoint/tie behavior, rectangle fill/outline/current-position semantics and leased backing/holes. Publication uses existing lifetime transaction; shared DC text/ROP state must be admitted before drawing and changes returned through the same owner.
- Thin cosmetic dash spans are DASH[18,6], DOT[3,3], DASHDOT[9,6,3,6], DASHDOTDOT[9,3,3,3,3,3]; phase follows original unclipped major-axis steps and continues around rectangle edges. Transparent gaps preserve destination; opaque gaps use DC background under the same ROP2. ROP2 values1..16 implement all binary source/destination truth tables, invalid values fail before mutation. Rectangle traversal honors arc direction. Explicit owner contract: null-pen fill uses original normalized half-open bounds, not decremented outline endpoints; Rectangle(0,0,4,4) fills16 pixels. Nonnull compatible 1x1 rectangle has zero-length outline segments and empty interior. Bound state snapshots include current position, ROP2, arc direction, DC pen/brush colors and background; no persistent second state record.

## 9

- Native drawing through GetDC/GetDCEx leases modifies canonical window backing independently of BeginPaint/EndPaint. Dirty tracking belongs to that backing DC; lease release cannot discard pending output. Font/metric/object queries and rejected or fully clipped draws do not schedule frames. No process-side surface registry or per-font publication.
- Message-pump flush snapshots dirty canonical window backings before blocking and publishes through the existing acknowledged compositor transport. GUI metadata lookup precedes GDI capture; no GUI/GDI lock, borrowed pixel slice or client lifetime gate crosses blocking transport. One bounded candidate pass per invocation; failures never cause an in-call retry loop.
- Idle Get/Peek flush updates the process output owner's last-idle timestamp; busy retrieval suppresses flushing within 50ms of that timestamp. Busy checks never extend the idle grace. Explicit whole-surface, EndPaint and auxiliary erase publication reserve through the same backing owner, including unchanged initial black pixels. Full native memory-DC presentation retains its entire surface before reserving the canonical window frame.
- Canonical dirty owner arbitrates in-flight generations. Capture/serialization failure preserves pending work; enqueue/completion failure restores or retains dirty state. Only actual Presented completion acknowledges the captured generation. Drawing during publication remains pending; stale completion cannot acknowledge newer pixels. Concurrent flushers cannot submit the same backing out of order. EndPaint explicit publication uses the same generation accounting rather than clearing arbitrary later writes.
- Hosted output-boundary tests drive real GdiManager storage and dirty state through capture, unlocked publication and completion. GetDC draw/release without EndPaint must produce a frame; clean/query-only/fully clipped work must not. Failed publication retries on a later invocation, concurrent writes survive acknowledgement, and omitted dirty marking or success-only publication must fail controls.
- Existing process GdiEntry owns OutputPump.last_idle_ns, initially zero. Idle flush records monotonic time and runs the dirty-only pass; busy flush skips while elapsed time since last idle is below50ms. Busy polling does not advance last_idle or generate dirty work. Explicit EndPaint publication bypasses pump timing but shares backing reservation/finish accounting. No timer registry or per-font throttle state.
- If another acknowledged flusher settles captured demand before explicit submission, unchanged canonical backing identity with no remaining demand completes without retransmitting stale pixels. Missing/replaced backing is invalid, not settled. Refreshing a stale capture never reintroduces an older surface over newer acknowledged pixels.
- Explicit EndPaint/erase capture marks full canonical backing pending even for unchanged zeros. PreparedFrame owns bytes and a generation snapshot, not an in-flight reservation; dropping it leaves canonical output demand flushable. Submission acquires reservation under GDI after current-owner validation, refreshes stale captured bytes under that lock, and finishes exactly once using actual completion. Missing current context cannot strand a reservation. Busy ownership never blocks reentrant submission: STATUS_PENDING means retained output awaits publication, not Presented. Transport failure releases ownership and reports STATUS_PENDING while retained output remains retryable; only actual Presented returns STATUS_SUCCESS. Raw EndPaint completes its validated paint/DC lifecycle for retained pending output without emitting a presentation milestone. Capture/owner validation failures remain errors. No automatic destructor acquires GDI while a caller may already hold it.
