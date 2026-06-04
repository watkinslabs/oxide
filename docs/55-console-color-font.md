# 55 In-kernel color-font console

DRAFT 2026-06-03. Dep:`28`,`47`,`48`,`49`,`50`.

Revises `49§2`,`49§7`,`49§13`,`49§15`,`50§14` for runtime-loaded multicolor console fonts, wide glyphs, combining marks, emoji clusters in `KD_TEXT`.

## 1

| Item | Proposal |
|---|---|
| Surface | VT/fbcon only; no userspace compositor dependency |
| Layout model | fixed-cell grid only |
| Width | 1-cell + 2-cell glyphs |
| Color | per-glyph RGBA with alpha blend into fbcon backing buffer |
| Load path | `KDFONTOP` installs font package or selects compiled-in default |
| Fallback | per-VT ordered fallback chain |
| Scrollback | stores text + attrs + width metadata, not rendered pixels |

## 2

| Goal | Required |
|---|---|
| Runtime custom font load | yes |
| Multicolor glyphs | yes |
| Wide CJK/full-width glyphs | yes |
| Combining marks | yes |
| Emoji presentation (`VS16`) | yes |
| Emoji ZWJ clusters | yes |
| Proportional layout | no |
| Arbitrary userspace text stack in kernel | no |
| HarfBuzz-class shaping for all scripts | no in v1 |

## 3

Current gap vs proposal:

| Area | Current | Proposal |
|---|---|---|
| Font source | built-in 8x16 ASCII bitmap | runtime-loaded font packages + fallback chain |
| Non-ASCII | `?` fallback | Unicode cmap + cluster lookup |
| Width | 1 cell only | 1 or 2 cells |
| Color glyph | fg/bg only | full RGBA glyph layers |
| `KDFONTOP` | ABI constants only | full ioctl plumbing |
| Storage | rendered pixels only | text cells + glyph cache + font objects |

## 4

Recommended architecture: **kernel console font package (`KCF`)**, not direct general-purpose TTF/OTF parsing in kernel.

Reasons:

- Color emoji needs more than PSF.
- Direct SFNT/OpenType parse + outline raster + color tables in kernel is too large for first landing.
- Offline conversion keeps kernel parser small, deterministic, testable.
- `KDFONTOP` still loads a custom font into the running system; source can be TTF/OTF/emoji fonts converted by a host tool.

## 5

`KCF` package contents:

| Section | Meaning |
|---|---|
| header | magic, version, package flags, cell size, glyph count, cluster count |
| cmap | codepoint/cluster → glyph or cluster id |
| width table | width in cells: 0,1,2 |
| mono bitmap table | optional 1bpp glyphs for text fonts |
| gray bitmap table | optional 8bpp coverage masks |
| color bitmap table | optional premultiplied RGBA glyph rasters |
| cluster table | ZWJ / variation-selector / combining sequence records |
| fallback metadata | optional package-local preferred fallback order |

Header sketch:

```c
struct kcf_header {
    u8  magic[4];      // "KCF\0"
    u16 version;       // 1
    u16 flags;         // HAS_MONO,HAS_GRAY,HAS_RGBA,HAS_CLUSTER
    u16 cell_w;
    u16 cell_h;
    u32 glyph_count;
    u32 cluster_count;
    u32 cmap_off;
    u32 width_off;
    u32 mono_off;
    u32 gray_off;
    u32 rgba_off;
    u32 cluster_off;
};
```

## 6

Font formats by support tier:

| Tier | Format | Role |
|---|---|---|
| required | PSF v1/v2 | compatibility, monochrome console fonts |
| required | KCF | native load format for mono + gray + RGBA |
| optional tool input | TTF/OTF + COLR/CPAL or CBDT/CBLC | converted offline to KCF |
| reject in v1 | SVG glyphs, sbix, variable fonts | parser/raster scope too large |

## 7

Per-VT font binding:

```rust
struct FontSet {
    primary: FontId,
    fallbacks: [FontId; N],
    cell_w: u16,
    cell_h: u16,
}
```

Rules:

1. VT keeps fixed cell size for active font set.
2. Font switch may change `(cell_w, cell_h)`; fbcon recomputes `(cols, rows)` and reflows visible text.
3. Font objects are global + refcounted; VTs bind by id.
4. Color and mono fonts may coexist in one fallback chain.

## 8

Render unit = **cluster**, not raw codepoint.

| Input | Resolution |
|---|---|
| ASCII / BMP scalar | direct cmap lookup |
| full-width codepoint | width=2 cluster |
| combining marks | merge into previous base cluster |
| `VS15` / `VS16` | text/emoji presentation selector |
| ZWJ sequence | cluster-table lookup first |
| missing cluster | fallback font chain |
| total miss | U+FFFD replacement cluster |

Stored screen cell model:

| Field | Meaning |
|---|---|
| `cluster_id` | resolved cluster/glyph key |
| `fg`,`bg` | text attrs for mono/gray glyph paths |
| `width` | 1 or 2 |
| `cont` | continuation bit for trailing half of wide glyph |
| `attrs` | bold, underline, inverse, blink |

## 9

Renderer changes for `49`:

| Stage | Work |
|---|---|
| cluster resolve | UTF-8 stream → cluster queue |
| glyph fetch | font set lookup + fallback |
| cache | raster/bitmap lookup by `(font_id, cluster_id, fg, bg, attrs)` |
| compose | blend glyph pixels into fbcon backing buffer |
| dirty tracking | mark 1-cell or 2-cell rect |
| flush | existing dirty-rect transfer path stays |

Blend rules:

1. Mono glyph: choose `fg`/`bg` per bit.
2. Gray glyph: alpha blend `fg` over `bg`.
3. RGBA glyph: premultiplied alpha over current framebuffer pixels.
4. Underline/inverse apply after glyph resolve, before dirty-rect flush.

## 10

Wide-glyph rules:

1. Width-2 cluster occupies `(col,col+1)` in one row.
2. Trailing cell stores `cont=1`; writes into trailing cell replace whole cluster.
3. Cursor on trailing half snaps to leading half.
4. Erase/insert/delete touching either half clears whole cluster.
5. Scrollback stores one cluster record, not duplicated halves.

## 11

`KDFONTOP` proposal:

| Op | Behavior |
|---|---|
| `KD_FONT_OP_SET` | load PSF or KCF blob from caller buffer |
| `KD_FONT_OP_GET` | dump active font package metadata or raw package bytes |
| `KD_FONT_OP_SET_DEFAULT` | select compiled-in default font set |
| `KD_FONT_OP_COPY` | bind another VT's font set |

New rules on existing ioctl:

- `flags` field identifies payload kind: `PSF`, `KCF`, `METADATA_ONLY`.
- Kernel validates header, lengths, cell bounds, glyph-count bounds, cluster-table bounds before install.
- Load failure returns `EINVAL` or `E2BIG`; never half-installs.

## 12

Memory policy:

| Item | Proposal |
|---|---|
| global font object cap | 64 MiB initial hard cap |
| single package cap | 16 MiB initial hard cap |
| per-VT binding cost | ids + cache refs only |
| glyph cache | global LRU, target 8 MiB initial |
| scrollback | text/attrs only; no pixel snapshots |

Failure policy:

- Package too large → reject load.
- Invalid cluster graph → reject load.
- Missing glyph in primary → fallback chain.
- Cache pressure → evict least-recent glyphs; never drop installed font object silently.

## 13

Recommended rollout:

| Stage | Outcome |
|---|---|
| A | wire `KDFONTOP` for PSF; per-VT font binding |
| B | wide glyph storage + erase/cursor/scroll correctness |
| C | combining marks + fallback chain |
| D | KCF mono/gray package loader |
| E | KCF RGBA glyph path + alpha blend |
| F | emoji cluster table (`ZWJ`,`VS16`) |
| G | cache + perf tuning + memory caps |

## 14

Specs touched if proposal is accepted:

| Doc | Change |
|---|---|
| `49` | replace 1bpp-only blit model with mono/gray/RGBA cluster compositor |
| `49` | tighten wide/combining invariants from aspirational text to concrete storage/render rules |
| `50` | define `KDFONTOP` payload kinds, load semantics, failure codes |
| `48` | clarify fbdev coexistence with RGBA console glyph composition |
| `47` | no UAPI change; confirm dirty-rect/flush assumptions still hold |

## 15

Test contract for first full landing:

- Load PSF via `KDFONTOP`; active VT switches cell size; text redraw remains correct.
- Load KCF mono package with non-ASCII cmap; `U+2500` and `U+2588` render without `?`.
- Width-2 glyph write + cursor motion + erase keep lead/trail cells coherent.
- Combining acute over `e` renders one visible cluster; backspace removes whole cluster.
- Color glyph load renders RGBA emoji over non-black background with alpha preserved.
- ZWJ family sequence resolves to one cluster when present in cluster table; falls back predictably when absent.
- Scrollback round-trip preserves cluster ids + width metadata.
- VT switch preserves per-VT font binding.
- `/dev/fb0` writes still coexist with fbcon redraw path.

## 16

Renderer configuration:

| Surface | Scope | Knobs |
|---|---|---|
| kernel cmdline | boot default | `console-font=`, `console-font-fallback=`, `console-emoji=on/off`, `console-aa=off/gray`, `console-blend=fgbg/rgba` |
| `KDFONTOP` | per-VT font binding | load/select/copy/default font packages |
| VT ioctl extension | per-VT render policy | fallback-chain order, emoji presentation default, width policy override for ambiguous-width codepoints |
| sysfs | global inspection | active renderer mode, cache stats, loaded font objects |

Rules:

1. Boot picks a default font set + renderer policy from cmdline.
2. Each VT may override font binding + render policy after boot.
3. Policy change never mutates stored text; fbcon re-renders from scrollback/state.
4. Renderer policy is constrained to fixed-cell semantics; no proportional mode.

## 17

Resolved decisions (were open; closed per Linux-equivalence + `00§14`):

| Q | Decision | Rationale |
|---|---|---|
| Complex-script shaping boundary | NO in-kernel GSUB/GPOS; console resolves codepoint/cluster + combining marks + emoji ZWJ/VS sequences only. | Linux fbcon is fixed-cell and does not shape Arabic/Indic — complex shaping is the userspace text stack's job (Pango/HarfBuzz over a real compositor). Kernel console ≠ shaper. Not a deferral: this IS the Linux console contract. Bidi/Arabic display rides the userspace GUI path, not the VT. |
| Authoring tool location | in-tree host tool `tools/kcf-mkfont/` (TTF/OTF+COLR/CPAL/CBDT → KCF). | Local-tooling principle (CLAUDE.md); mirrors `tools/spec-lint`. No external repo dep for a build-time converter. |
| Package signing/policy | unsigned; load gated by `CAP_SYS_TTY_CONFIG` (root) only. | Linux `KD_FONT_OP_SET` is a privileged ioctl with no signature check. Font-blob trust = process privilege, same as Linux. Code signing is `18`'s module concern, orthogonal to console fonts. |
| Default built-in color font | none built in; compiled-in default = the existing mono console font (`49§2`). RGBA/emoji KCF packages load at runtime via `KDFONTOP`. | Linux ships only a mono builtin (VGA/PSF); rich/color fonts are loaded, never baked into the kernel image. Keeps the kernel binary small and matches the Linux boot-console surface. Not a subset: full color/cluster support exists, just runtime-loaded. |

Boundary note (display vs console-font): the **graphical framebuffer must be live** before any of this renders — that is the GPU/fbdev bring-up in `33`/`34`/`48` (virtio-gpu queue setup → `DRIVER_OK` → scanout), independent of `55`. `55` governs what fbcon *draws into* that framebuffer; it does not make the framebuffer appear.
