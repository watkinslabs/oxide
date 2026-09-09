# Handoff — Notepad callback routing held by stack regression

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`
Branch B3630-paint-region-collapse. Main read-only. Goal remains active:
Notepad borders, buttons, menus, About, Save/Open and dropdowns must work.

## Published

Draft PR #7680, remote last verifiedcc0e21ff2. Harness opens all five menus,
About, Save As and Open; checks captions, file types, Cancel and content round
trip below the measured menu.25 Python tests pass. X11 empty backing and
obsolete configure fixes have90 compositor tests. Atomic rejected resize
fix03758d7e3 has529 window-manager tests. No runtime success claimed.

## Local only — do not bypass the new stack regression

KI-0641 callback routing implemented inb6447279e; nested callback synchronization
fixed1787af1ac, with later local stack-lifetime refactoring. Procedure-bearing
Configure packets enter remote_positions. Owner thread runs CHANGING,
NCCALCSIZE and CHANGED; canonical geometry changes after the callback.
Callback-free windows retain direct delivery. Compositor-origin geometry does
not echo unless the application adjusts it or a nested position intervenes.
Flags are computed at consumption, preserving queued returns to original size.

3255 syscalls lib tests and29 production position-boundary tests pass.
Positive controls: direct packet mutation, bypassed callback chain, lost queued
resize, suppressed correction, nested position losing display synchronization.
Both kernel feature gates checked on the current source; inspect final log
`/tmp/B3630-configure-final-feature.log` before asserting completion.

KI-0868: best measured Windows route depth19200 B versus baseline19168 B;
window_raw18880 versus18848. Gate has338 already-over-budget paths and7664 B
exception path, but the extra32 B belongs to this change and has NOT been
bypassed. Latest source restores the best measured version; x86 binary from
last stack run may still contain the discarded snapshot-helper experiment.
Best result `/tmp/B3630-configure-stack10.log`; baseline chain
`/tmp/B3630-configure-old-paths.log`. Initial increase was160 B. Do not infer
success from unchanged failure count. Source/refactor is committed locally;
callback work has NOT been pushed. Revalidate stack before publication.

Useful entry points: position/remote.rs pump, prepare_compositor, take_current;
position/live.rs start_inner, after_changing, calculate_client, commit.
Position Origin models Local/Remote/Compositor; nested same-HWND callbacks mark
pending Compositor origins Remote so outer commit corrects display geometry.

## Runtime failure evidence

One acceptance run76178 failed with "GNOME session marker appeared without a
rendered desktop frame". QEMU79681 exited; no owned guest remains. Artifacts
`target/B3630-acceptance`, buildB3630-dialogs. GNOME reports running21.114s,
framebuffer remains console ending13.670s. Notepad never launched (KI-0865).
SessionVT2 active, DRM open; session DBus responds, DisplayConfig times out;
GNOME main thread waits on a private futex. Cause unconfirmed. GDB failed to
produce a backtrace (KI-0866); tracer killed and GNOME resumed before timeout.
Do not use another boot to debug. No callback fix has runtime verification.

KI-0861 saved UART: custom dialog600x30 at72.517 becomes750x1 after parent and
child resize callbacks. Source layout resizes child to parent client size;
requested parent rect and returned NCCALCSIZE rect are absent from that log.
KI-0859 captions still unproven; old measurement-cleared claim was unsupported.

Open: stack regression, desktop startup, actual dialog/border behavior, both
architecture runtime results. Plan/evidence scratch/B3630-notepad-verification.md.
Default ARM sysroot gaps KI-0421/KI-0691 remain; local completed Fedora sysroot
only proved compositor cross-build. Pre-existing gates KI-0019 remain separate.
