# Handoff — Traced worker status and notification repairs

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`
Branch B3630-paint-region-collapse; draft PR #7680. Verify local/remote SHAs
before assuming the last push finished. Main remains read-only. Goal active:
Notepad borders, buttons, menus, About, Save/Open and dropdowns must work.

## Implemented

- Harness: all five menus open/dismiss; About, Save As, Open, visible captions,
  file-type dropdowns, OK/Save/Open/Cancel, saved-content round trip below menu.
  25 Python tests pass with positive controls for wiring and false evidence.
- X11 empty backing and stale configure notification fixes:90 compositor tests,
  including real Xvfb regressions. x86 and ARM compositor builds pass; ARM used
  task-local completed Fedora sysroot (default gaps KI-0421/KI-0691 remain).
- Atomic rejected resize03758d7e3:529 window-manager tests pass.
- KI-0641 b6447279e + nested fix1787af1ac: procedure-bearing Configure packets
  enter remote_positions; owner thread runs CHANGING/NCCALCSIZE/CHANGED before
  canonical geometry commits. Callback-free windows keep direct delivery.
  Origin Local/Remote/Compositor controls retrieval and geometry publication;
  nested same-HWND positions mark pending compositor work for correction.
- Queued move/size flags computed at consumption, preserving rapid returns to
  original size. Display geometry does not echo unless application corrects it.
- KI-0868 fixed232e63fd5: prepare_current completes raw-argument planning before
  callback execution. Measured Windows routes19136/18816 B, baseline19168/18848.
  Over-budget paths338 ->336; every remaining entry is unchanged or smaller.
  No allowance changed. Archived baseline/fixed stack logs named KI0868.
- 3255 syscall lib tests and30 callback-boundary tests pass, with positive
  controls for packet wiring, callback execution, queue ordering, application
  corrections, nested updates and failed/no-op preparation outcomes.

Only pre-existing KI-0019 gate failures may be bypassed. Callback publication
was held while stack use regressed; that regression is now removed. Keep PR
DRAFT until runtime requirements are verified. Plan/evidence:
`scratch/B3630-notepad-verification.md`.

## Runtime evidence and next work

One acceptance run76178 failed: "GNOME session marker appeared without a
rendered desktop frame". QEMU79681 exited; no owned guest remains. Artifacts
`target/B3630-acceptance`, buildB3630-dialogs. GNOME reports running21.114s,
framebuffer remains console ending13.670s. Notepad never launched (KI-0865).
SessionVT2 active, DRM open; session DBus responds, DisplayConfig times out;
GNOME main thread waits on a private futex. Cause unconfirmed. GDB failed to
produce a backtrace (KI-0866); tracer killed and GNOME resumed before timeout.
No callback fix has runtime verification. Do not use another boot to debug.

KI-0861 saved UART: custom dialog600x30 at72.517 becomes750x1 after parent and
child resize callbacks. Source layout resizes child to parent client size;
requested parent rect and returned NCCALCSIZE rect are absent from that log.
KI-0859 captions unproven; old measurement-cleared claim unsupported.
Open: desktop startup, actual dialog/border/menu behavior and both architecture
runtime results. Do not merge or mark goal complete on hosted test evidence.

## Debugger repair and next step

KI-0869 fix e7dde8192 changes actual x86 user selectors to0x33/0x2b and
kernel selectors to0x10/0x18. GDT reload, STAR, entry and task frames agree;
ptrace remains a raw frame conversion.230 HAL and3256 syscall tests pass;
old-selector/old-descriptor-slot positive controls fail. Both feature gates
pass. Built ELF selector operands inspected. Stack336 failures unchanged, no
new/worsened path vs prior branch report; exception7664 B unchanged.
Selector repair published in draft PR7680; verify latest local/remote SHA.
Hosted gate180 crates and both feature gates pass. No new boot.

KI-0870 fixed05071e0f1 in draft PR7680. Complete image publication
is now in exec::vdso::map_into, reached by syscalls::vdso::map_into_current
from both exec paths. ELF parsing uses the existing shared parser. The full
image and page-rounded extent survive, including non-PT_LOAD section metadata.
Five boundary tests in syscalls/src/vdso/tests.rs inspect real VMA backings
for both generated images, second-page metadata, rejected layout and missing
data page. Original truncation reproduces three failures in final owner.
241 ELF-loader tests pass (one existing ignored report);3261 syscall tests
pass. Both feature gates pass. x86 stack336 failures unchanged. ARM release
build passes;277 failing stack paths and6368 B exception path exactly match
an exact pre-change source build. Candidate sources restored and verified.
ARM logs /tmp/B3630-vdso-stack-arm{,-baseline}.log; candidate ELF retained at
target/B3630-vdso-fixed-arm.elf. Default ARM ELF is the baseline comparison:
rebuild/stage the candidate for any verification boot.
Other logs /tmp/B3630-vdso-{boundary-red,full-tests,feature,stack}.log.
No new boot. Keep draft until runtime acceptance succeeds.

GDB17.1 source check: missing /proc/self/mem causes a ptrace memory fallback
on a stopped thread; the warning alone is not proof of a backtrace blocker.
The composed GNOME root RPM database confirms gdb-headless17.1-1.fc42 and
gnome-shell48.8-1.fc42. Desktop mutex cause remains unknown.

KI-0871 fixed0fe94a760: syscall attach calls sched::live::ptrace_attach::attach
after validation. Metadata publication and the initial signal live there;
ATTACH routes SI_KERNEL SIGSTOP to the target private queue. Real group with
ptrace-stopped leader reproduces old shared-queue failure. SEIZE preserves
options and sends no signal. Both focused tests and all2019 scheduler tests
pass; both feature gates pass. /tmp/B3630-attach-{red,green,sched,feature}.log.
Both release builds pass; complete stack reports match pre-change baselines:
x86336 paths/7664 B exception, ARM277 paths/6368 B exception, none new/worse.
Logs /tmp/B3630-attach-stack-{x86,arm}.log. Default ARM ELF now contains this
candidate, replacing the earlier comparison baseline. No new boot or runtime
cause established. Verify publication state before assuming push finished.

KI-0874/0875 fixeddc3fbe15e: tracer SIGCHLD uses worker TID in receiver PID
namespace; real-parent group-stop notifications use leader identity. Wait
snapshots/selectors use the task-number helper. Important correction: mapped
worker wait selection already passed before the change. Registry insertion
installs PID mappings; the wrong TGID fallback was an unmapped snapshot case,
not proof that the failed GDB run selected the wrong task.

Traced worker exits now survive ThreadGroup::finish_exit and are published
from live::mark_done's exit notification path. Traced exit policy preserves a
waitable zombie even with SIGCHLD ignored. Separate tracer reap consumes a
worker without handing it back as a leader zombie. Final traced worker and
deferred leader both remain waitable; non-leader notification still uses
SIGCHLD when live count reaches zero because the leader remains retained.
Ten new tests exercise actual retirement, real groups/namespaces, SIGCHLD and
peek/reap.2029 scheduler tests pass; six restored-defect controls fail, then
full restored suite passes. Both feature gates pass. ARM release build passes;
277 stack failures/6368 B exception exactly match preceding branch report.
x86 release build passes;336 failures/7664 B exception also match exactly.
No new/worsened stack entry. Lint4723 findings/46 regressed keys identical to
clean main in this invocation; KI-0019. Logs /tmp/B3630-wait-{controls,controls-green,
retirement-red,final-worker-red,feature,stack-arm,stack-x86}.log.

GDB17.1 uses ATTACH for its LWPs, not SEIZE/INTERRUPT. Keep diagnosis focused
on the path the retained failed debugger run used. No GNOME cause or Notepad
runtime behavior verified by these repairs. No new boot.

Remaining: KI-0872 INTERRUPT and KI-0873 already-group-stopped attachment.
INTERRUPT wrongly publishes stop_pending/code/siginfo from the tracer before
posting process SIGSTOP. Required mechanism arms jobctl TRAP_STOP, wakes an
interruptible target (or LISTENING stop) and reports on the tracee when parked.
sched/task/sigwake.rs and syscalls/exit_to_user.rs currently do not consider
jobctl traps; exit_to_user/signal.rs dequeues real signals only. Existing
live/stop.rs retrap branch reuses the original code AND StopKind, while
jobctl::wake_retraps excludes PtraceResume despite resume_clears retaining the
trap latch. Already-group-stopped attachment also lacks TRAPPING/wait for
STOPPED-to-TRACED transition, including SEIZE. Do not repair these by changing
INTERRUPT to private SIGSTOP; it must not alter signal queues. Use canonical
jobctl/stop state, preserve FPU snapshot/restore through ptrace stop owner,
and reread complete primary ptrace/signal implementations before editing.

Caption trace follow-up: raw measurement now records count, DC snapshot and
stock-metrics refusals; callback allocation and metrics/extent copyout failures
also use bounded TEXTMEASURE-DROP. Both feature gates pass, log
/tmp/B3630-caption-trace-feature.log. KI-0859 claimed by B3630 and corrected:
empty measured label and successful button caption lookup remain hypotheses.
The ntdll procedure addresses are forwarding functions, not evidence of a
DLL relocation defect. Still missing direct button/client/label tracing.
