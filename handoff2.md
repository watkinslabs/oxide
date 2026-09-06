# Notepad runs; paint is the last link — 2026-09-06

First command: `git log --oneline -3 && tools/issues.sh --show KI-0427`

## Where this got to

Notepad **executes, creates its main window and its EDIT child, and enters its
message loop**. Four acceptance milestones pass: `[WINDOWS-PE-START]`,
`[WINDOWS-NT-UNIX] entry`, `[WINDOWS-USER32] create-window`,
`[WINDOWS-USER32] get-message`. It does not paint, so no window is visible.

24 PRs merged (#7477–#7504), every one a measured defect. The chain, in order,
each found by instrumenting rather than guessing:

| Defect | PR |
|---|---|
| launch ran as root holding the user's env (`nsenter --env` keeps root creds) | 7483 |
| `DISPLAY` absent — gnome-shell creates it after exec | 7484 |
| compositor required optional EWMH GNOME never sets; swallowed its own failure | 7485 |
| **`RtlUTF8ToUnicodeN` read `ULONG` lengths as 64 bits, including a pointer's upper half** | **7492** |
| **`default_window_proc` had no `WM_NCCREATE` arm, so it returned FALSE and aborted every window** | **7501** |
| registry endpoint, desktop authority, process identity (earlier wave) | 7478–7482 |

The two bolded ones are the substantive kernel bugs. The rest of the PRs are
diagnostics that are worth keeping: every teardown, rejection and refusal on the
window path now names itself.

## The remaining defect — KI-0427

`GetMessage` hands the application `WM_PAINT` (0x0f) for hwnd=1. Nothing ever
calls `NtUserBeginPaint` (ordinal 0x1327) — zero times in a whole run — so the
damage is never validated and WM_PAINT is redelivered unboundedly (>30k
deliveries at one timestamp).

`WINDOWS-WNDPROC-ENTER` appears only for kernel-initiated create callbacks,
never for a queued message. **Dispatching a retrieved message to its window
procedure does not reach the procedure.** That is the whole remaining gap.

Ruled out, with evidence: the window state is right (main window shows with
client rect 729x546 and `pending-paint=1`), and two hosted tests in `ipc`
(`showing_a_window_with_geometry_leaves_it_pending_paint` and its complement)
hold that model.

## Also open

- **KI-0426** — the bridge handshake is 5000ms and compositor startup measures
  3448ms, of which `xcb_connect` alone is 2775ms. 69% of budget, so it
  intermittently times out. Do not just widen it: the launcher should wait for
  its own child before binding.
- **KI-0424** cross-process desktop DC; **KI-0425** unwired station/desktop bind.
- Boots are flaky independent of this work: ~2 in 10 wedge early with an
  identical kernel.

## Method that worked

Instrument, run once, read, fix. Two false trails were killed by checking
whether the instrument could even have shown what was inferred — the raw-entry
marker covers four ordinals only, so its silence proved nothing, and a fifo
added to capture diagnostics ate the ones it existed for. Neither the Wine
sources nor NT semantics are on this machine; nothing was asserted from memory.

## Commands

```sh
./tools/windows-notepad-acceptance.py          # ~8 min, self-driving, one attempt
L=$(ls -t target/windows-notepad-acceptance/uart-*.log|head -1)
awk '!/DRM-ATOMIC/ && !/BOCHS-RESOURCE/' $L | grep -n "GETMESSAGE\|WNDPROC\|USER32\]\|GDI\]"
```

Gates are red on `main` itself (KI-0287, KI-0318, KI-0019, KI-0423); pushes used
the specific `SKIP_*` flags at the maintainer's instruction.
