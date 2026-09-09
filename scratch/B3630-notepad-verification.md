# Notepad verification

| Status | Requirement | Evidence needed | Branch |
|---|---|---|---|
| In progress | About and push-button captions | Open About; visible OK/license captions; real button closes it; hosted causality check for defect | B3630-paint-region-collapse |
| In progress | Save As, Save, Open | Save new file, edit/save, New, reopen; edited token inside document crop | B3630-paint-region-collapse |
| In progress | File-type dropdowns and Cancel | Visible expanded filters in both dialogs; Cancel returns with document intact | B3630-paint-region-collapse |
| In progress | Menu dropdowns | All five opening/dismissal checks wired; runtime rendering and dispatch still unverified | B3630-paint-region-collapse |
| Open | Border redraw and moves | Move/resize/occlusion evidence; preserved contents; no drawing outside surface | B3630-paint-region-collapse |
| Open | Cross-architecture verification | Both kernel gates; both applicable runtime acceptance paths | B3630-paint-region-collapse |

Harness: `tools/notepad_dialogs.py`, called by `run_desktop_checks` before closing.
Offline: 23 Notepad tests pass. Positive controls: removing dialog call,
accepting title text as document content, accepting title as button caption
all turn the new tests red; restored green. First-line document fixture also
reproduced a crop false negative; crop now starts below measured File menu text.

KI-0861: UART ShowWindow result is client geometry, already 750x1, before
paint clipping. Client geometry/layout is the next boundary to investigate.
KI-0859 remains unproven: last instrumented run never opened About.

Pre-push lint-ratchet: same 4723 findings / 46 regressed keys reproduced on
clean main afa38ce09. KI-0019; only SKIP_LINT_RATCHET used for initial note push.

KI-0864 reproduced using the real Xvfb backend: 750x0 became 750x1;
an obsolete empty-backing event also undid a later 60x30 resize. Both tests
red before their respective fixes. Empty logical windows now use 1x1 backing;
backing events do not rewrite logical extents; configure events older than
the pending request are rejected using the expanded XCB sequence number.
Compositor suite: 90 passed, including actual one-row windows and serial wrap.
Notepad runtime consequences remain to be verified.

Pre-push hosted gate: 180 crates pass. Test-build gate fails in unchanged
ipc/syscalls test targets (unused settings helpers; missing paint_trace test
module; unused mark_exiting). No branch change touches those crates. KI-0019;
SKIP_TEST_BUILD_GATE is the only additional bypass for this pre-existing gate.

ARM compositor release build passes with the Fedora sysroot completed locally
at target/B3630-arm-sysroot from cached Fedora 42 libgcc/gcc/libxcb/libXau/
libxkbcommon/libxkbcommon-x11 RPMs. System sysroot is unchanged; KI-0421 and
KI-0691 remain applicable to the default environment. Link uses that sysroot,
its GCC linker-script directory and its lib64 as rpath-link (not runtime rpath).

Both kernel feature gates pass. Stack gate fails on unchanged kernel paths:
exception-entry oxide_fault_print_rust 7664 B > 7200 B; longest paths exceed
stack budget. KI-0019; only SKIP_STACK_GATE added to prior named bypasses.

Acceptance run 76178: fresh branch kernel and staged runtime, one QEMU boot.
GNOME reports running but QMP still displays boot console. Notepad has not
launched. SSH on this VM (localhost port 22363 added through QMP) confirms
active VT2/session and open DRM descriptors. Do not claim dialog verification.

Desktop diagnosis on the same VM: session-bus ListNames responds and lists
org.gnome.Mutter.DisplayConfig, but GetCurrentState times out. Main GNOME
thread 394 stays in syscall 202, op 0x80, expected 2, no timeout, at user
address 0x5625e5a088c8. This is a private futex wait, not proof of its cause.
Thread snapshot: /tmp/B3630-guest-threads.txt. GDB could not produce a backtrace
(KI-0866); owned tracer 1111 killed after its timeout failed to detach;
GNOME restored to State S / TracerPid 0. Do not attribute later timeout
duration entirely to the original stall: debugger briefly stopped GNOME.
Draft PR: #7680. Runtime acceptance still unverified.

Final acceptance result: exit 1, "GNOME session marker appeared without a
rendered desktop frame". Runner76178 and QEMU79681 both exited; no live VM
remains. UART audit passes with no Windows calls, since Notepad never launched.

Menu coverage: all five dropdowns must acquire their expected entries after
opening and lose them after Escape. Existing document words are rejected as
ambiguous baseline evidence. 25 Python tests pass; removing the menus call
makes the wiring test red (/tmp/B3630-menu-hook-red.log).

KI-0861 narrowed timeline from retained incident log: custom dialog 0x20001b
is 600x30 at72.517. Parent 0x200004 resizing callbacks occur72.546-72.557;
custom dialog resizing callbacks72.562-72.733; its next ShowWindow sees750x1
at72.785. File-dialog initialization explicitly resizes the custom template
to the parent's current client size after arranging controls. Neither the
parent's requested dimensions nor NCCALCSIZE's returned rectangle are logged
at that boundary. No additional cause is established by this inspection.

KI-0867 fixed03758d7e3: invalid retained client geometry is checked before
set_rect. Regression reproduced the partially committed outer rectangle on
refusal, then passed after validation moved ahead of mutation. All529
win32_window tests pass with the branch IPC lib (no lint suppression).
Logs /tmp/B3630-refused-resize-red.log and /tmp/B3630-window-suite.log.
KI-0641 remains open: incoming compositor Configure bypasses the existing
owner-thread NCCALCSIZE transaction and retains constant insets. A wrapping
menu or size-dependent border needs the actual callback; rejecting invalid
insets atomically does not implement that calculation. Existing bounded
remote_positions queue and position/live.rs callback chain are the integration
boundary to use; avoid a second geometry owner or a clamped-client workaround.
No new boot: runtime verification remains outstanding for this kernel change.

KI-0641 fixedb6447279e: bridge apply_event now sends procedure-bearing HWND
Configure packets to the canonical remote_positions queue. Its owner consumes
work through the production position callback chain; callback-free windows
keep direct delivery. Relative move/size flags are decided at consumption so
a queued return to the original size survives the preceding resize. Accepted
display geometry does not echo; application-adjusted geometry does publish.
New tests cross the packet-to-queue and queue-to-callback boundaries, adopt a
size-dependent client rectangle, enforce owner-thread execution and resume
retrieval once. Positive controls bypass the queue, drop a queued original-size
return, or suppress application corrections; each fails its regression.
Restored:3255 syscalls lib tests and28 production position-boundary tests pass;
both kernel feature gates pass. Runtime verification still outstanding.

Local follow-up1787af1ac and later refactoring: nested same-window position
changes mark a pending compositor origin as Remote, ensuring the outer commit
corrects display geometry.29 callback-boundary tests pass, including a failing
positive control without that mark;3255 syscalls lib tests also pass.
KI-0868 holds callback publication: best stack10 result19200/18880 versus
baseline19168/18848 for legacy/window_raw routes. The32 B increase is new,
even though338 existing paths and the7664 B exception path still fail.
No new callback commit has been pushed; the pre-existing stack bypass was NOT
used for it. Latest source restores stack10 after the separate snapshot-helper
experiment worsened the route to19232. Revalidate the built artifact when
continuing. Runtime requirements remain unverified; goal not complete.

KI-0868 fixed232e63fd5: queue extraction and planning return a prepared request
before callback execution. Raw argument storage does not survive into the
callback chain. Current legacy route19136 B versus baseline19168; window_raw
18816 versus18848. Complete failure-list comparison:338 baseline,336 current,
no new or worsened entries; exception path remains7664 B. Both named stack
reports retained in scratch/archive/B3630-KI0868-stack-{baseline,fixed}.log.
No stack allowance changed. Only pre-existing KI-0019 failures remain.
3255 syscall lib tests and30 callback-boundary tests pass. Positive control
that replaced failed preparation with success fails the new outcome test.

KI-0869: native user CS/SS now0x33/0x2b; kernel CS/DS moved to0x10/0x18
so the user selector slots hold actual user descriptors. Reload assembly,
MSR_STAR, initial task frames and saved syscall frames share GDT constants.
Ptrace conversion is unchanged and reports those actual frames. Native
debugger architecture selection now receives its64-bit discriminator.
230 HAL tests and3256 syscall tests pass. Positive controls restore the old
selector or populate the descriptor in its old slot: selector, descriptor and
task-frame-to-ptrace checks fail, then pass after restoration. The NT startup
context check requires the new pair and rejects the former pair.
Built ELF disassembly: GDT reload loadsDS0x18/CS0x10; syscall entry pushes
SS0x2b/CS0x33. Both feature gates pass. Stack comparison with the preceding
branch ELF:336 failing entries, none new or worsened; exception7664 B unchanged.
Logs /tmp/B3630-selector-{asm,descriptor-red,ptrace-red}.log and
/tmp/B3630-selectors-{red,green,syscalls,feature,stack}.log.
No new boot; KI-0866 also includes missing process-memory files, malformed
vDSO metadata and incomplete debugger detach, which this change does not fix.

KI-0870: vDSO publication now retains the complete ELF image, including
section headers/names beyond PT_LOAD, with the full page-rounded reservation.
The shared ELF parser validates a single RX segment at offset/vaddr0 with
filesz==memsz. `exec::vdso::map_into` owns publication; the existing syscall
adapter supplies mm/image/machine/vvar. Both exec entry paths still call it.
Five syscall boundary tests inspect the real destination VMA backings for
both generated images, second-page metadata, refused layouts and absent data
page. The original mapper fails both image tests; restoring truncation in
the final owner fails all three metadata tests. Admission/size controls also
fail their respective tests.241 ELF-loader tests pass (one pre-existing
ignored ordinal report);3261 syscall tests pass. Both feature gates pass.
x86 stack failure lists are identical to the pre-vDSO-repair branch:336 task
paths and the7664 B exception path; no new/worsened failure.
Evidence: /tmp/B3630-vdso-{mapping-red,controls-red,boundary-red,full-tests,
feature,stack}.log. ARM release build succeeds;277 failing paths and the
6368 B exception path are identical to an exact pre-change source build.
No new/worsened failure. ARM reports /tmp/B3630-vdso-stack-arm{,-baseline}.log;
candidate ELF retained at target/B3630-vdso-fixed-arm.elf. Default ARM ELF
currently contains the comparison baseline; rebuild/stage candidate for boot.
Runtime remains unverified.

Debugger source check: failed /proc/self/mem open makes native memory access
fall back to ptrace on a stopped thread. Missing process-memory files are
still a defect, but that warning alone does not prove the backtrace blocker.
No new GNOME cause established; KI-0865/KI-0866 remain open.

KI-0871: authorized attachment publication moved to
`sched::live::ptrace_attach::attach`, called after syscall permission checks.
ATTACH sends SI_KERNEL SIGSTOP through the canonical private thread queue;
SEIZE preserves options without generating a signal. A real thread-group test
with a ptrace-stopped leader reproduces the shared-queue defect, then passes
with thread routing. Both focused tests and all2019 scheduler tests pass;
both architecture feature gates pass. Logs /tmp/B3630-attach-{red,green,sched,
feature}.log. Release/stack verification pending at this note.
KI-0872 records incorrect INTERRUPT publication and absent jobctl trap handling;
KI-0873 records missing group-stopped attachment transition. Neither is fixed
by changing ATTACH signal routing. No runtime verification or new GNOME cause.
