# Native GDI text callback

FROZEN 2026-09-06. Dep:`31fk`,`31n`,`31l`,`52`,`53`,`54`.

## 1

- Raw `NtGdiExtTextOutW` adapter snapshots logical font height/width/weight/italic, XRGB text/background colors and DC handle from canonical GDI owner, drops owner lock, invokes native callback.
- Callback registration resides in existing process callback registrations; continuation resides in existing Task callback stack. No second DC, thread or TLS registry.
- Bootstrap registers after native NTDLL attachment and native thread factory installation. Child callbacks require Running native attachment; initial Task requires registered native factory. FS/TPIDR_EL0 remain libc-owned, GS/x18 remain TEB-owned.
- Kernel copies header, UTF-16 text and optional advances before redirecting return frame. Counts, address arithmetic, flags and font size validate before allocation/copy. Usercopy failure leaves continuation and PC/SP unchanged.
- Native callback uses existing `windows-gdi::RasterFont` and `Gdi` upload façade. Font bytes come from installed userspace font file; no kernel font parsing. Missing/invalid font fails registration.
- Callback completion restores original PE PC/SP and ARM link register from tagged LIFO continuation; drawing returns BOOL success only after all requested fill/blit operations succeed, query DWORD results remain unmodified. Native ELF callback must finish before forced native-thread termination consumes its continuation.
- Metrics and extents use the same cached substituted RasterFont as drawing, including width=0. Kernel does not synthesize character width. UTF-16 cumulative extents repeat the completed glyph position for both units of a surrogate pair; malformed units use the renderer's replacement glyph. Measurement sums the same unkerned floating-point advances as rasterization, rounding cumulative positions upward.
- TEXTMETRICW is 60 bytes: actual font line ascent/descent/gap, alphabet average advance, maximum mapped-glyph advance, selected resource weight/italic, cmap first/last BMP character, available replacement/space characters, fixed-pitch TrueType modern-family flags, virtual device DPI 96. Underline/strikeout and overhang are zero for these untransformed resources.
- Raw text-state result policy: MoveTo accepts absent old-POINT; supplied old-POINT receives signed coordinates before position mutation, and copy failure prevents mutation. SetDCDword changes canonical state before required old-DWORD copyout; absent/faulting copyout returns FALSE without rollback. Previous foreground/background XRGB becomes COLORREF exactly once; already-COLORREF brush results and non-color DWORDs remain unchanged. Owner failure performs no copyout; BOOL success requires successful owner operation and every required copy.

## 2

| Field | Contract |
|---|---|
| Selector | `NtQueryVirtualMemory`, information class 1007 |
| REGISTER | a0=0, a1=entry, a3=return entry, a4=version 1; NTSTATUS |
| COMPLETE | a0=1, a1=zero-extended DWORD result; tagged continuation required; draw/measure produce BOOL, queries retain charset/count/GDI_ERROR |
| ALPHA_UPLOAD | a0=2, a1=dc, a3=non-premultiplied ARGB pixels, a4=width low32/height high32, a5=x low32/y high32; contiguous rows; NTSTATUS |
| MEASURE_COPY | a0=3, a1=copied MeasureRequest pointer, a3=MeasureOutput pointer; active tagged native GDI callback required; NTSTATUS |
| MeasureRequest | repr(C), 88 bytes: version/size u32, dc u64, kind/count u32, height/width/weight i32, italic u32, max_extent i32, flags u32, text/metrics/extent/fit/cumulative u64; kind 1=metrics, 2=extent; same version 1 |
| MeasureOutput | repr(C), 88 bytes: metrics[60] bytes, width/height i32, fit/count/reserved u32, cumulative pointer u64; reserved=0 |
| Measurement bounds | same 4096-unit/font limits; metrics requires count=0 and metrics pointer, ignores flags; extent requires SIZE pointer; flags=0 selects UTF-16, any nonzero flags select glyph indices; all pointer additions checked before allocation/copy |
| Measurement copyout | kernel snapshots header/result and entire bounded cumulative buffer before writing; validates count/fit and monotonic positions; optional fit limits copied cumulative prefix, absent fit copies all positions; negative max extent interpreted as unsigned; copy fault returns failure, never success after partial copy |
| Header | repr(C) TextRequest, 112 bytes, version/size u32; dc u64; x/y i32; flags/count u32; text/advances u64; rect[4] i32; height/width/weight i32; italic/foreground/background/has_rect/reserved/background_mode/alignment u32; current_x/current_y i32; reserved=0 |
| Payload | at most 4096 WORDs, optional count i32 advances or 2*count for PDY; copied into callback-owned stack storage |
| Flags | ETO_OPAQUE=2, ETO_CLIPPED=4, ETO_GLYPH_INDEX=0x10, ETO_IGNORELANGUAGE=0x1000, ETO_PDY=0x2000; other flags rejected, never misinterpreted as Unicode |
| Rectangle | required for opaque/clipped flags; ordered signed coordinates |
| Font | height absolute 0..256 pixels, zero selects default positive cell height 16; positive height chooses integer em size using resource unitsPerEm/(OS/2 winAscent+winDescent), hhea ascent-descent when sum is zero, rounded then reduced if rounded cell exceeds requested height; negative height directly specifies em size. Width absolute 0..256, weight=0..1000, italic=0/1; width=0 uses resource advances; nonzero width scales glyph X coordinates/coverage and natural advances by requested width divided by resource alphabet-average advance; explicit lpDx remains caller logical units |
| Resource substitution | installed /usr/share/fonts/liberation-mono-fonts/LiberationMono-{Regular,Bold,Italic,BoldItalic}.ttf; weight>=600 chooses bold; italic chooses italic variant; callback font tuple omits canonical LOGFONT face name, so substitution is declared rather than claiming face matching |
| Raster | existing renderer's 16M-pixel tile bound; existing GDI blit bounds and DC clipping |
| Background | mode 1 retains glyph coverage in ARGB and source-over blends into canonical DC; mode 2 uploads opaque XRGB; ETO_OPAQUE still fills explicit rectangle in either mode |
| Alignment | left/top value 0; other values rejected before drawing, never silently treated as left/top; current position copied but not mutated |

## 3

- ABI tests pin size, malformed versions/counts/flags/rectangles/advances and checked copy layout.
- Hosted native-render tests load installed TrueType font, rasterize typed UTF-16 token, upload glyph pixels into real GdiManager surface and prove non-background pixels without any second registry.
- Native callback preserves real pthread TLS/TID across rendering; missing font and failed uploads return failure.
- Both architecture gates cover callback entry/return register ABI; primary owns gates and final desktop verification.

## 4

- Selected-resource queries use the same Task callback, DC snapshot, resource bytes and cached RasterFont as drawing; no mutable HDC/font mirror. Substituted resource reports ANSI charset, actual OS/2 Unicode/codepage signature, actual SFNT tables and cmap glyph identities.
- QueryRequest repr(C), 80 bytes: version/size u32, dc u64, kind/flags u32, height/width/weight i32, italic u32, first/count u32, input/output u64, table/offset/capacity/reserved u32. Reserved zero; version 1. Kinds 1=charset, 2=font data, 3=glyph indices, 4=ABC widths, 5=outline metrics. Input is copied WORD[count], at most 4096, or absent for ABC sequential range. Font bounds follow §2.
- QUERY_COPY selector a0=4, a1=copied QueryRequest pointer, a3=QueryOutput pointer; QueryOutput repr(C), 24 bytes: result/length u32, data/reserved u64. Kernel requires active tagged continuation, validates operation-specific output length, snapshots at most 16MiB before destination copy, returns NTSTATUS. Native completion returns API failure on copy failure.
- Charset returns ANSI_CHARSET=0 with optional 24-byte FONTSIGNATURE, six little-endian DWORDs from selected resource OS/2 Unicode/codepage ranges; flags ignored. Failure returns DEFAULT_CHARSET=1. No fabricated success signature.
- Font data table DWORD stores tag bytes little-endian; table=0 selects whole installed resource. Null buffer or zero length queries full table size regardless offset. Nonzero length reads min(requested, full table size) bytes starting at offset; crossing table end fails GDI_ERROR=0xffffffff. Missing/malformed table fails, never zero-filled success. Resource and copy bound 16MiB.
- Glyph query maps each WCHAR independently, including surrogate units, to selected font cmap. Missing characters use actual OS/2 default-character glyph, or 0xffff when flags bit 1 requests missing markers. Return count or GDI_ERROR. ABC query flags bit 2 means glyph indices, bit 1 integer ABC; otherwise ABCFLOAT. Adapter normalizes first/last to bounded count before callback; absent input enumerates first+index. Widths derive from the same scaled glyph geometry and advances as renderer.
- Outline query serializes 64-bit OUTLINETEXTMETRICW, 232-byte fixed record followed by terminated UTF-16 resource names; name members are offsets, not host pointers. Null output returns required size; bounded short buffer receives the exact prefix, including offsets beyond the copied prefix, and returns copied size. Numeric fields derive from selected resource tables and cached font scaling. No invented names/metrics.
- Glyph rendering accepts ETO_GLYPH_INDEX=0x10, ETO_IGNORELANGUAGE=0x1000 and ETO_PDY=0x2000 in addition to opaque/clipped. Glyph-index input is WORD glyph IDs, never decoded as UTF-16; PDY advances contain exactly 2*count signed integers, paired X/Y displacements. IGNORELANGUAGE bypasses shaping; caller-provided glyphs/placements pass unchanged to the existing font renderer. Rectangle required only for opaque/clipped. All advances copied before callback; invalid glyph indices fail before pixel mutation.

## 5

| Raw ordinal | Windows-order arguments | Query construction |
|---|---|---|
| 0x1225 | HDC, FONTSIGNATURE pointer, DWORD flags | kind 1; optional output; flags retained/ignored by provider |
| 0x11fe | HDC, DWORD table, DWORD offset, buffer, DWORD length | kind 2; null buffer normalizes ignored capacity to zero |
| 0x1204 | HDC, WCHAR pointer, INT count, WORD output, DWORD flags | kind 3; negative or over-bound count fails GDI_ERROR before callback |
| 0x11e6 | HDC, UINT first, UINT last-or-count, WCHAR pointer, ULONG flags, output | kind 4; indices bit or supplied input means argument 2 is count; otherwise unsigned inclusive range length; null output fails even for zero count |
| 0x1211 | HDC, UINT capacity, outline pointer, ULONG options | kind 5; null output normalizes ignored capacity to zero; options retained/ignored by provider |

- Decoder consumes normalized Windows argument order; scalar high halves truncate to DWORD, pointers/HDC retain all 64 bits. All signatures fit six normalized arguments; raw x86 entry must fetch logical stack slots 4/5 only when required by signature. Descriptor and raw entry call identical decoder.
- Unknown ordinal stays unclaimed; recognized short/invalid calls return that API's failure, never fall through to unrelated syscall dispatch. No input/output dereference occurs in decoding. Query count/address/resource bounds follow §4 before callback.
- Route obtains selected Font from canonical DC snapshot, releases owner before native entry, copies height/width/weight/italic faithfully including width 7, validates request, then returns native entry result unchanged. Missing snapshot returns charset 1, data/glyph GDI_ERROR, ABC/outline zero. No fabricated default font or second registry.
- Hosted boundary tests execute decoder/route against real GdiManager selection and pending-delete lifetime; pin ordinal signatures, high-half truncation, all pointer positions, ABC range/count distinction, bounds, failure domains, and callback-result passthrough. Positive control must corrupt a decoded argument and turn a boundary test red.

## 6

- EDIT paint via TabbedTextOut/ScriptTextOut preserves default DC alignment; status DrawText computes centered/right text coordinates without changing TA flags. No new alignment requirement is inferred from DrawText format flags.
- Raw NtUserCallOneParam ordinal 0x133d, selector 6 queries system COLORREF; selector 7 queries protected system HBRUSH. Arguments are unsigned 32-bit color index and selector; scalar high halves ignored. Other selectors remain unclaimed by this child.
- System color roles, palette and protected brushes remain canonical GDI owner state (`31fk§5`). Color query converts owner XRGB to COLORREF once; brush query returns the owner's published typed identity unchanged. Neither query changes DC selection/current position or owns a second cache. Unknown color index returns zero, failed brush allocation/publication returns NULL.
- Status background and non-diagonal DrawEdge depend on these color/brush queries followed by existing SelectBrush/PatBlt. Theme and optional size-grip geometry remain independent owners. Hosted tests use actual canonical brushes and pixels, assert deletion protection/repeated identity and failure/unknown-selector behavior.

## 7

- Raw NtUserSystemParametersInfo ordinal 0x15cb has four arguments: UINT action, UINT parameter, output pointer, UINT flags. Action SPI_GETNONCLIENTMETRICS=0x29 consumes caller cbSize at output; parameter/flags do not replace cbSize. Child claims only this action; invalid pointer/copy/size returns BOOL FALSE. Allowed cbSize 500 (legacy) or 504; output is precisely that many bytes, never beyond the legacy record. Other actions remain their owners' work.
- Canonical default nonclient profile lives with immutable GDI stock descriptions; no mutable settings mirror. At profile DPI 96, border=1, scroll dimensions=16, caption/menu dimensions=18, small-caption dimensions=15, padded border=0. Five complete LOGFONTW records derive from DEFAULT_GUI_FONT; caption weight=700, other weights=400, DEFAULT_CHARSET=1. Stock face/pitch/size retained; actual resource substitution remains §2. This profile does not claim registry/theme overrides or system-DPI changes are integrated.
- Query kind 6 carries 504-byte profile as 252 WORD input units, dc=0 because system settings are not an HDC query, capacity=caller cbSize. Font fields unused/zero. Existing same-Task native callback and QUERY_COPY apply; output result=1 and length=capacity. No second Task or font registry.
- Native owner normalizes border>=1, caption width/scroll width/scroll height>=8; menu height>=2+real menu tmHeight+tmExternalLeading; caption and small-caption heights>=2+corresponding real tmHeight. Complete fonts and dimensions serialize at fixed offsets; status LOGFONT begins316, message408, padded-border500. cbSize retained. Missing font resource/invalid snapshot fails; unmeasured zeros are never success metrics.

## 8

- Non-display GetSystemMetrics consumes §7 canonical 96-DPI default profile, independently of compositor availability. Scroll width indices 2/3 use max(scrollWidth,8); thumb/arrow indices 9/10/20/21 use max(scrollHeight,8). Border 5/6 always 1; dialog frame 7/8=3; frame 32/33=3+max(border,1); edge 45/46=2. Icon 11/12 and cursor 13/14=32; small icon 49/50=16; caption width 30=max(captionWidth,8), small-caption width 52 and menu width 54 retain profile dimensions. No second settings registry.
- Font-dependent indices 4/15/31/51/53/55/57 consume the same normalized profile as SPI_GETNONCLIENTMETRICS: captionHeight+1, menuHeight+1, captionHeight, smallCaptionHeight+1, smallCaptionHeight, menuHeight, captionHeight+6 respectively. No estimated font-height success.
- Query kind 7 carries the same 252-WORD canonical profile, cbSize=504, dc=0, first=metric index, output/capacity=0. Supported index required before launch. Native normalization returns positive scalar metric with zero output bytes through existing QUERY_COPY/COMPLETE; missing resource or malformed profile returns 0. Callback dispatch payload remains unchanged through raw route, including ARM continuation registers.
- Display indices 0/1/76..80 remain fresh compositor snapshots; non-display settings never synthesize screen dimensions. Unknown indices remain 0, not a claim of implemented hardware/environment metrics. Scalar index truncates to signed low DWORD. Tests pin scroll/caret/icon defaults, profile sharing, snapshot independence, font-dependent callback passthrough and real-font normalization.

## 9

- Status part painting first queries RectVisible. Raw NtGdiRectVisible=0x1258 takes HDC and pointer to four signed DWORD rectangle coordinates; result BOOL. Unknown ordinals remain unclaimed; recognized malformed calls return FALSE, never NTSTATUS. HDC admission precedes input copy; full 16-byte pointer range validated, copy failure returns FALSE.
- Visibility queries snapshot the canonical DC effective application/paint/surface clip (`31fk§1`) before copying user memory outside GDI locks. MM_TEXT identity coordinates remain the existing DC mapping contract; no independent transform or region registry. Rectangle endpoints are ordered; zero-area rectangles and edge-only contact are invisible; any positive-area overlap is visible. Invalid/deleted DC is FALSE. Queries never alter pixels, clip, selection or current position.
- Hosted boundary tests call the production decoder with a real GdiManager clip snapshot, cover reversed/empty/extreme rectangles, clipped-out status parts, paint/application intersection, resizing, invalid handles, pointer failures and no mutation. Removing clip intersection must fail a positive control.
- Exact paint-region amendment: visibility snapshot is an owned PaintRegion, never its bounding box. Canonical paint coverage is clipped by the existing effective application/surface bounds; absent paint coverage becomes that single rectangle. Snapshot and query intersection use PaintRegion's existing fallible operations, preserving holes/disjoint islands and failing FALSE on allocation failure. No per-pixel enumeration or duplicate clipping predicate. Snapshot precedes input copy and remains independent of later DC changes/deletion. Tests compare hole queries against actual clipped raster pixels and deliberately replace exact coverage with its bounds to prove failure.

## 10

- EDIT selected-text painting queries system indices 13 (highlight) and 14 (highlight text); monochrome edges and WS_BORDER EDIT frames query index 6 (window frame). Canonical initial XRGB values are 0x000a246a, 0x00ffffff and 0x00000000 respectively. Same system-role lookup and protected brush cache as `31fk§5`; equal RGB values do not collapse distinct system-role brush identities.
- Existing system-color decoder converts highlight to COLORREF 0x006a240a exactly once. Selected-text drawing temporarily uses opaque highlight background and highlight-text foreground, then restores previous attributes; lookup itself does not mutate any DC. No new registry or special-case selected-text raster path.
- Normal statusbar sunken outer DrawEdge uses shadow/highlight indices 16/20; raised outer uses light/dark-shadow 22/21. Normal/soft/flat rectangular edge tables require no other new colors. Monochrome window-frame query is separately admitted, not described as the normal statusbar branch.
- Boundary tests query each role through raw color/brush ingress, paint actual canonical pixels, verify protected/distinct/stable identities and immutable DC selection/attributes during queries. Missing role or omitted COLORREF conversion must fail.

## 11

- Caption-button painting saves current text color through raw NtGdiGetDCDword=0x11ef, three arguments HDC/method/output DWORD. Method 9 queries text color; related existing text-owner methods 1/2 query background color/background mode. Result BOOL; exactly four little-endian bytes written on success. Full pointer/HDC preserved; method truncates to low DWORD. Unknown ordinal unclaimed; malformed/invalid calls return FALSE without output mutation.
- Query obtains existing shared-aware canonical text snapshot: bound DC reads current validated client attributes, unbound DC reads private owner attributes. No setter, second attribute cache, DC creation, lease/origin mutation or renderer callback. XRGB colors convert through existing client COLORREF codec exactly once; mode retains raw DWORD. Invalid owner/shared snapshot, unknown method, pointer overflow, null destination or failed copy returns FALSE. Other non-text DC methods require their actual attribute owners, never fabricated defaults.
- Hosted tests drive production query/decoder with canonical DC attributes and direct shared-record color changes, validate four-byte copy and BOOL return, invalid admission/failure ordering, high-half truncation, and no state mutation. Removing COLORREF conversion must fail a control.
