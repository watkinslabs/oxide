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
