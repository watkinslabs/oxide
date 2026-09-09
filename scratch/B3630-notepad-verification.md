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
feature}.log. Both release builds pass. Complete stack failure lists are
identical to pre-change branch reports: x86336, ARM277, with7664/6368 B
exception paths. No new or worsened entry; no allowance changed. Reports:
/tmp/B3630-attach-stack-{x86,arm}.log. Default ARM ELF is now the candidate.
KI-0872 records incorrect INTERRUPT publication and absent jobctl trap handling;
KI-0873 records missing group-stopped attachment transition. Neither is fixed
by changing ATTACH signal routing. No runtime verification or new GNOME cause.

KI-0874/0875: tracer stop/exit SIGCHLD now carries the worker TID in the
receiver namespace; real-parent group-stop notification uses the group leader.
Wait candidates/snapshots use the task-number helper. Mapped worker selection
already passed before this change: registry insertion configures PID mappings;
the original broad wait-identity hypothesis was disproved. The old unmapped
snapshot fallback did use TGID and now has a failing positive control.

Actual live::mark_done now preserves and publishes traced worker exits.
ThreadGroup retirement no longer marks a traced worker reaped. Exit publication
uses the traced disposition even when the tracer ignores SIGCHLD, and a
separate tracer consumes worker zombies without the leader-only handback.
A final traced worker and its deferred leader both remain waitable. The
retained leader still makes a non-leader exit a SIGCHLD notification even
after the live counter reaches zero. Leader wait eligibility remains delayed
while siblings survive; that is not evidence of a wait-selection defect.

Ten new scheduler tests use real tasks, groups, PID namespaces, queued records
and the actual retirement entry. All2029 scheduler tests pass. Six controls
restore the wrong fallback, stop/exit identity, premature retirement, missing
exit publication hook or erroneous worker handback; each fails its regression.
The original retirement path independently failed four tests. Logs:
/tmp/B3630-wait-{identity-red,retirement-red,final-worker-red,controls,
controls-green,feature}.log. Both feature gates and release builds pass.
Complete stack reports match the pre-change branch exactly: x86336 failing
paths/7664 B exception and ARM277/6368 B. No new/worsened entry. Logs:
/tmp/B3630-wait-stack-{x86,arm}.log. Lint4723 findings/46 regressed keys match
clean main exactly in this invocation (/tmp/B3630-wait-{lint,main-lint}.log).
No new boot; no GNOME startup cause established.


## Wine profile selection and visible run, 2026-09-09

| Status | Branch | Evidence |
|---|---|---|
| Implemented | B3630-paint-region-collapse | KI-0878: release/debug build, artifact, package and physical guest catalog identities; explicit selection through composition, staging, cached launch and wrapper |
| Committed locally | packages:B3630-wine-profiles | 6830f27d0530148550646cfa95c582ea67826383; no remote configured |
| Committed locally | images:B3630-wine-profiles | 553217b1bd369f34a9e41e24ad81870ec967e0ad; no remote configured; pre-existing .dist-old-layout untouched |
| Running, not acceptance-complete | B3630-paint-region-collapse | User-requested GTK QEMU PID708994; namespace notepad-debug-696997; kernel built from current worktree; Wine11.16-debug |

Both full Wine builds completed:729 PE modules/30 Unix libraries. Release
user32 has no button diagnostic string; debug does. Named RPMs built through
packagectl, metadata refreshed, source image composed with OXIDE_WINE_PROFILE=debug.
Actual RPM database selects oxide-wine-debug-11.16-1.fc42; release absent.
Image user32 SHA256 bab3fe3426d20eaa2696af28aa84058fcde96fe7c1d9c43c4e33c6234c9a86db
matches debug artifact. Debug input ID000982e8e976863f0a29925ab7426d09808a3e61c125c18decc4cf77f27af5da;
release input IDa39c76acd7d7a95a6d0fba693301630ebbadd2ff756b353ffdcb9e56c4091046.
Profile-only source validation and full staged payload validation pass;
requesting release against the debug source fails. Both actual xtask cached
entry points reject wrong profile before kernel build or QEMU.

Verification:95 xtask tests pass/1 existing ignored,19 payload tests pass,
28 Notepad harness tests pass,5 builder cache tests pass,17 package tests pass,
2 image helper tests pass. Positive controls remove package/profile/image
stamp checks and cached verification hooks: corresponding tests fail.
Logs /tmp/B3630-profile-{cache-green,payload-cached,notepad-tests-final,
packages-final,images-final,existing-red,existing-green}.log.

Visible run log target/boot-logs/x86_64-20260909-140413.log; QMP/UART endpoints
under target/B3630-user-debug. Early console frame advanced to a rendered
GNOME desktop and Notepad with user-entered text. Do not interfere with user
input. User exercised an OK button: trace reports caption OK, measurement22,
label rectangle(56,3)-(73,25), draw result1. These observations do not prove
all dialog/dropdown/redraw requirements; acceptance remains incomplete.

Geometry tracing174ef9636 removes ab216dba9 stack regression: complete final
x86/ARM reports exactly match prior caption-trace baselines (336/277 failed
static paths, exception7664/6368 B). KI-0877 archived fixed with literal SHA.


## Guest-owned UART names, KI-0879

Status: implemented; Branch:B3630-paint-region-collapse.
Acceptance captures win32u ordinals from the validated staged disk before
boot; UART audit uses that immutable map. Missing DLL preserves raw ordinals,
never names from another Wine installation. Real ext4 fixture verifies selected
DLL extraction and missing-DLL behavior.19 audit tests and29 harness tests pass;
removing the preboot capture hook fails its wiring test. Current source debug
image yields1540 names; retained live UART audit has no unclaimed/refused calls.
Logs /tmp/B3630-audit-{guest-tests,harness-tests,capture-red,capture-green}.log.


## Final automated run759158 and harness failures

Status: failed before dialog checks; Branch:B3630-paint-region-collapse.
Manual QEMU708994 exited. Separate B3630-debug-final image validated, then
QEMU779614 reached GNOME and Notepad. Run759158 ended exit1: expected token
oxide-b3630-final not present inside measured crop(148,122,877,165).
Retained full frame shows the window ends y692 and text suffix -0-final.
Source image remains named debug; output target/B3630-debug-final and
/tmp/B3630-debug-final-acceptance.log. No unclaimed/refused calls in audit.

KI-0880: inset frame columns cross dark edit-control border at y165/166;
outer chrome columns remain continuous to y691. Repair measures outer edges.
Real retained PNG regression and synthetic recessed border regression pass;
original inset columns fail both. Correct full crop still rejects missing
full token, preventing the measurement repair from laundering the input failure.

KI-0881: send-key schedules each press/release through a virtual-time delay
queue; input-send-event directly dispatches events without waiting for that
queue. A send-key Ctrl+A followed by immediate token text can invoke shortcuts
before Ctrl release. Correctness driver now emits complete immediate chords
and text on one ordered event path. Removed comparative timed-typing probe
from correctness run; token retrieval cadence reporting retained. No sleep,
retry or timeout increase. Production input-call test tracks held modifiers
and proves exact token delivery with no key left held. Restoring timed chord
fails. No later boot or successful final acceptance is claimed.

## Actual File Open and dialog control lookup, 2026-09-09

- Automatic run804065 (B3630-debug-ordered) painted the complete token and passed A1/A2/A3 after92373c14a. File-menu OCR failed before any item selection; cleanup terminated that VM. User correctly rejected this as dialog verification.
- Persistent visible run used the same staged named debug payload. Actual pointer clicks File(168,156), Open(194,195), pointer parked(930,700). Evidence target/B3630-dialog-live/file-menu-painted.png and open-dialog-stable.png; commands.jsonl journals QMP actions. Open produced a black strip, no usable controls.
- Serial target/boot-logs/x86_64-20260909-143112.log: parent100005 and custom child10001c retain750x484 bounds. Prior750x1 claim does not describe this run. Toolbar10001a creation style54020944 carries nonsensical geometry, fails publication with transport3; bridge refusals also name100019 and100014. Open caption lookup/measurement/draw returns success. Sizegrip10001b repeatedly returns c0000002 from WM_PAINT.
- QEMU808134 was later absent from ps; serial ends mid-line at169.713s. Exit cause unknown. No live VM as of14:45UTC; revalidate before launching. Retained evidence establishes an attempted dialog, not a successful one.
- KI-0883: GW_CHILD and GW_HWNDFIRST returned bottom while enumeration/NEXT walked down. Dialog child→sibling-list→identifier lookup missed control0x471 in a hosted regression (None vs HWND4). Correct first/last endpoints; verify both directional walks and unrelated-parent exclusion. All1512 IPC lib tests pass; both architecture debug-all checks pass. Runtime effect unverified.
- KI-0882: select actual File→Open item before broad menu checks, require Open/Cancel captions, preserve a failed live VM and sockets by default. OXIDE_NOTEPAD_KEEP_ON_FAILURE=0 requests termination. Full menu clicks release before capture and park cursor clear of captions. Shutdown timeout fails acceptance.
- KI-0884: UART audit now recognizes window-create and bridge-refused markers. Re-auditing actual Open trace reports four findings instead of PASS.43 dialog/failure/desktop-order/audit tests pass. Five targeted controls restoring early menu ordering, removing Open actions, restoring termination, or omitting error patterns each fail assertions; restored production code passes.

-322669c2a implements KI0882/0883/0884; remote ca548c4f5 verified. Both release builds pass; complete stack rows match prior x86/ARM reports exactly (358/299 rows). Hosted gate180 and both feature gates pass on push; only previously documented KI0019 skips used.
-KI0885: raw_callback::message_call lacks scrollbar selector029a. Selected debug DLL disassembly identifies17006aa30 as ScrollBarWndProc_W forwarding to the scrollbar procedure, whose WM_CREATE/WM_PAINT path uses that selector. Unhandled selector returns STATUS_NOT_IMPLEMENTED; no paint completion. Open, not repaired by traversal change.

## Dialog click dispatcher, KI-0886

- Live832847 controlled click655,463 at202.179s targets About button100007; each WM_NCHITTEST returns0 and only WM_SETCURSOR follows. dispatch-actions.jsonl records injected pointer/down/up; no VM termination.
- DefaultProc compared screen lParam against parent-client-relative state.rect. It now calls default_proc_state, which reuses canonical rect_query Window mapping. No new coordinate registry or forced HTCLIENT fallback.
- Actual compositor-pointer enqueue→hit-test→retrieval test covers nested ancestors, client inset, parent movement, negative screen positions, down/up identity/client coordinates, and excluded right/bottom/outside points. Original default hit returns0 instead of1; repaired path passes.
- Actual production dispatch.rs fixture confirms its call site consumes the screen query. Restoring old call site fails Some(0) vs Some(1); restoration passes116 integration tests. Fixture source dependencies updated to actual key latch/compositor position admission; untested nonclient frame seams fail loudly if called. KI0604 wider hardware/menu coverage remains open.
- All3262 syscall lib tests pass; both feature gates and release builds pass. Stack comparison has no increased/new reported path:13 x86 rows decrease, ARM unchanged; existing exception reservations unchanged. Running inspection VM still has earlier kernel.

KI-0887: native child windows clipped pixels published by a parent-backed
control DC because the presentation GC used the default child clipping mode.
GC subwindow mode now includes child windows; the GUI DC owns the clip.
Real Xvfb regression publishes a partial parent frame beneath a child:
old call leaves all four child pixels unchanged (RED); corrected call changes
only the two covered pixels (GREEN). Full compositor suite:97 tests pass.
Runtime verification remains outstanding; pointer trails and stale menu pixels
are not yet attributed to this defect.
Both compositor release targets build. ARM uses the existing completed
Fedora sysroot at target/B3630-arm-sysroot; default system sysroot still lacks
the previously recorded XCB/XKB/libgcc link inputs (KI-0421/KI-0691).

KI-0885 control-state foundation: optional storage on the canonical HWND,
creation identity/disabled flags, SCROLLINFO result consumption, raw range
message behavior and teardown/isolation tests. No raw procedure wiring yet.
Three targeted tests fail when initialization is removed; restored code passes
all1515 IPC tests. This is not a completed scrollbar implementation.
KI-0888 claimed before changing shared scroll-info policy: disabled flags and
page-only/no-fields transitions need correction before the control consumes it.
Control-state foundation721f8120d builds both release kernels. Stack reports
match53cf05cdf exactly on both architectures:358/299 reported rows, no
new/increased path; existing336/277 failures and7664/6368 exception bytes.

KI-0888: canonical scroll flags replace the redundant disabled boolean;
zero-page position clamping, page-only hiding, disable-without-hide and
unchanged redraw follow the state contract. Without redraw, changed flags
request arrows only and retain every thumb/track pixel. Five initial policy
regressions fail old behavior; restored action predicate and full-bar raster
each fail their boundary test. Final IPC suite1522, syscall suite3262,
nonclient raster boundary and joined scrollbar boundary pass; both feature
architectures pass. Full release/stack verification for this change pending.
KI-0889: scrollbar fixture imports the production action module and current
worktree adapters, replacing duplicate logic and absolute main-tree paths.
Position completion and raster observation remain explicit fixture seams.
