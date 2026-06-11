1. **Fix `VT_WAITACTIVE` for deferred/process-mode switches**
   - `VT_ACTIVATE` now defers correctly when the current VT is in `VT_PROCESS`, but `VT_WAITACTIVE` still behaves like a stale bookkeeping check instead of waiting for the switch to complete.
   - Linux-style `VT_ACTIVATE(n)` then `VT_WAITACTIVE(n)` is still broken whenever the switch goes through the release/acquire handshake.
   - Fix this first because it breaks the basic userspace VT-switch contract even though the new handshake code exists.

2. **Make `VT_RELDISP` validate the real owner**
   - The release/ack path exists now, but I do not see strong ownership validation on the caller that completes or refuses a pending switch.
   - The foreground VT's registered process-mode owner should be the only task allowed to answer the handoff.
   - Without this, the code has the shape of Linux VT process mode but not the trust model.

3. **Stop tracking VT process ownership as a bare pid only**
   - `VT_SETMODE` records enough state to send rel/acq signals, but it still looks fragile against task exit and pid reuse.
   - If the owner dies or the pid gets recycled, later VT signaling can target the wrong task.
   - This is the next real correctness hole in the process-mode implementation.

4. **Finish the VT ioctl surface that is still only partial**
   - The code is much better than before: `VT_GETMODE`, `VT_SETMODE`, `VT_RELDISP`, LEDs, resize, `TIOCLINUX` subfunction 6, and font/unimap plumbing now exist.
   - But important gaps still remain, especially `VT_SENDSIG` and the rest of `TIOCLINUX`.
   - The problem is no longer "constants only"; it is "implemented enough to look real, but not enough to be Linux-compatible."

5. **Turn VT resize into a real live console resize**
   - `VT_RESIZE` / `VT_RESIZEX` now update VT-side size state and push a winsize update path, but that still does not look like a full end-to-end resize of the actual per-VT screen state.
   - The visible fbcon `Vc`, backing buffers, and numbered-console state all need to move together.
   - Right now resize still looks closer to metadata plus signal delivery than a real console geometry change.

6. **Collapse the repo onto one TTY implementation**
   - This is still the biggest structural bug.
   - The new VT code now does real switching, but it still calls `tty::live::set_foreground`, and numbered console paths still depend heavily on `tty::live` for reads, termios, pgrp/session state, wakeups, answerback injection, and polling.
   - As long as `tty::live` and the newer `TtyStruct` / `NTty` core both own behavior, Linux compatibility will keep drifting because there are two sources of truth.

7. **Move console ioctl/termios behavior into the real TTY core**
   - `TtyStruct::ioctl()` still falls into the thin `core_ioctl()` stub path, while much of the real behavior lives in syscall-side decode glue.
   - That means the tty object itself is still not the authoritative place for tty semantics.
   - The unified tty core needs to own the behavior directly, not depend on special syscall routing to become "real."

8. **Make blocking tty reads signal-interruptible and finish `VTIME`**
   - The core tty path is still simplified compared with Linux.
   - `VTIME` is explicitly still not implemented, and the blocking-read path does not yet look fully signal-aware in the Linux sense.
   - This matters for shells, job control, and programs that rely on real noncanonical timeout behavior.

9. **Finish PTY hangup / flow-control / line-discipline edge cases**
   - PTY support works in the broad sense, but it still looks approximate around hangup, stopped output, and some line-discipline semantics.
   - Those simplifications usually do not show up in trivial tests, but they break real userspace once job control and terminal multiplexers get involved.
   - This is lower than the VT-switch and architecture issues, but it is still real Linux-compat debt.

10. **Widen font support beyond the current narrow path**
   - This part is improved: the old "renderer is basically ASCII-only" complaint is no longer fair.
   - The new font/unimap code is real, but it still hard-restricts some font shapes, especially widths above 8.
   - So text rendering is no longer the worst problem, but it is still not at Linux-console coverage yet.

11. **Keep the old fix list, but mark these earlier items as partly fixed**
   - Real DSR/CPR answerback now exists.
   - VT process-mode switching is no longer just enum constants.
   - Scrollback now has a real control path.
   - Font/unimap support is no longer missing entirely.
   - The remaining problems are mostly integration, ownership, and split-stack issues rather than total absence of implementation.
