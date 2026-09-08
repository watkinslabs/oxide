# Handoff — Windows control captions and the bar band

Dialog push buttons render frames with **no caption text**. Static text in the
same dialog renders. Separately, wide dialog controls repaint as long thin
horizontal bars, and content lands outside its own surface, worst after a
window move. Session did NOT crack the caption defect. Everything below is
measured, with the log kept so nothing needs re-booting to re-check.

## Merged this session

| PR | What |
|---|---|
| #7678 | Instruments: `[WINDOWS-WINTEXT]`, `[WINDOWS-TEXTMEASURE]`, `[WINDOWS-TEXTMEASURE-DROP]`; hosted test for the fit-bearing extent query |
| #7679 | Findings from the instrumented boot (doc + whole UART log) |

Rows: `KI-0859` captions, `KI-0860` bar band, `KI-0861` one-pixel update
regions, `KI-0862` measurement cleared.

Evidence log: `scratch/archive/B3629-uart-one-pixel-update-regions.log`
(boot 2026-09-08 18:18; booted ELF verified to contain the instrument strings,
so zero counts are real absences, not an unbuilt trace).

## Ruled OUT — do not re-open without new evidence

- **`NtUserInternalGetWindowText` / `GetWindowTextW`.** Wine's static control
  fetches its caption through the *same* call the button uses, and statics
  render. Proven from the log, not argued.
- **`DrawTextW` unimplemented or answering without drawing.** The statics'
  runs come out of it.
- **The text measurement path.** Full Notepad session: `[WINDOWS-TEXTMEASURE]`
  0 and `[WINDOWS-TEXTMEASURE-DROP]` 0 — nothing refused, nothing answered a
  zero-area box. Fit-bearing extent query (`lpnFit != NULL`, the arm only
  `DrawText` uses) verified end to end by hosted test, positive control both
  directions.
- **Collapsed glyph rows / raster stride.** The same frame renders legible
  multi-row glyphs in the menu bar, the static and the edit control through
  the same rasterizer. A stride bug is not selective.
- **Window style.** The default-button rectangle appears on one button and not
  the other, so `GWL_STYLE` comes back correct.

## What the caption defect must be

Button and static differ in exactly one thing: the button **measures** its
label (`DT_CALCRECT`) and hands the box to Wine's draw-state helper, which
returns without drawing when either dimension is zero — no text run at all,
frame intact. The static is left/top aligned and consumes neither the measured
width nor the line height, so the same bad answer is invisible there.

Confirmed from the log: both buttons run `WM_PAINT`, and issue **zero** text
runs and **zero** refusals, with the run trace's budget unspent. So the failure
is above the kernel's text run, in the label rectangle.

Measurement is cleared (above). That leaves the **client rectangle** the button
measures into. **This is the untested link and the next thing to check.**

## Strongest open lead: the update region / client rect

Same run, first `[WINDOWS-PAINT-REGION]` per window:

| window | region | verdict |
|---|---|---|
| `0x200001` Notepad main | 729 x 528 | correct |
| `0x200002` edit child | 723 x 522 | correct |
| `0x200004` Open dialog | **750 x 1** | one row |
| `0x20000e` | **360 x 9** | nine rows |
| `0x200010` | **332 x 1** | one row |
| `0x20001b` | **750 x 1** | one row |
| `0x20001d` | **300 x 1** | one row |

First paints, not partial damage. Creation geometry is sane —
`[WINDOWS-PE-WINE-CREATE-ARG]` for child `0x20000b` under parent `0x200004`
gives `y=0x16c cx=0x70 cy=0x20` — so the **update region** collapsed, not the
control. `0x20001b`'s region is 750 wide, wider than a control of that family,
which matches the reported "renders garbage outside the surface".

A wide control repainting one row of its text **is** the bar band. That band is
a damage-region defect, not a raster defect.

Two files to read first, in this order:

- `crates/kernel/ipc/src/win32_window/paint_damage/owner.rs`
  - `paint_region()` clips the damage by `client_rect(id)`. Confirm both are in
    the *same* coordinate space. A client-local region clipped by a screen-space
    rect yields exactly a sliver.
  - `paint_region_to_screen()` translates by `record.client_rect` for **every**
    ancestor including the window itself. If those rects are stored absolute
    rather than parent-relative, the origins sum and the region lands outside
    the surface — which is the reported symptom verbatim.
- `crates/kernel/syscalls/src/nt_window/paint_prepare/live.rs` — where the
  region reaches `set_paint_region_for_current` and the trace prints its bounds.

Note the earlier About-dialog capture had **correct** full-size control regions
(130x28 buttons, 428x20 statics) and still lost its captions. So the one-pixel
regions may be a second defect rather than the caption cause. Do not assume one
fix closes both; prove it.

## Harness gap that cost this session

`tools/windows-notepad-acceptance.py` types a token and **never opens Help /
About**, so the button path is never exercised and the new instruments never
fire on it. Before the next boot, add an About step (the runner already has
`keys()` / `type_text()` QMP helpers) and hold long enough for the dialog to
paint. Otherwise a zero marker count means nothing.

## First command for the next session

```
tools/issues.sh --show KI-0859 && \
sed -n '1,110p' crates/kernel/ipc/src/win32_window/paint_damage/owner.rs
```

Then add the About-dialog step to the acceptance runner and boot **once**.

## Box notes

- Pre-push is red on `main` for `lint-ratchet`, `test-build-gate` and
  `stack-gate` (`KI-0019`); skip only the gate that names itself and say so.
- Lanes share `/home/nd/oxide/kernel/target`: a concurrent build takes the
  cargo package lock and a kernel LTO link can sit for tens of minutes. Give
  every lane its own `CARGO_TARGET_DIR`.
