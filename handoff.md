# Notepad handoff — 2026-09-10

User requested committing all work, merging PR7680 and refreshing main. Notepad is NOT fixed.
This file is current; handoff2.md predates the final uncommitted stack correction.

## Start here

```sh
cd /home/nd/oxide/kernel-B3630
git status --short
cat CLAUDE.md
```

Active worktree: /home/nd/oxide/kernel-B3630.
Branch: B3630-paint-region-collapse.
HEAD: 5789e8b18748653acee7e7f88a0e0b2584f58a5c.
Last remote verification at handoff: 795fcf64bf5b27ef97d4d4ab9840d6b4045ed34c.
A push is still pending; do not assume later commits reached origin.
Main /home/nd/oxide/kernel is read-only, afa38ce09. Only these two worktrees exist.
Draft PR7680: https://github.com/watkinslabs/oxide/pull/7680.
Merge is explicitly authorized; do not report full Notepad acceptance.

User priorities: working Notepad borders, buttons, menus, Open/Save, About,
file-type/encoding/filename dropdowns, mouse selection, repaint and round trip.
Use the supplied canonical reference sources; no Wine patches, forks or duplicate
runtime catalogs. Wine11.16 release/debug profiles are explicit and independent
of kernel build profile. Read repository rules before editing.

## What was actually verified in the guest

Latest VM4192826 booted GNOME and one Notepad instance. Runner4192767 recorded
one controlled Notepad PE start at54.219s, tid13c6. Initial document token passed;
the harness clicked File, then Open. It failed the Open dialog observation.

Namespace fix ca07ea578 is verified: screen DCs now return nonzero handles.
Filename edit changed from1px to15px high; *.txt and other control text are
readable. The same standalone desktop/DC probe changed from exit7 to exit0.
KI0924 was closed. Its real bootstrap test failed ParentMissing before repair;
4 boundary,104 object and2029 scheduler tests passed afterward.

Open still has severe white/black stripes, missing title/decoration and a
blank/black file list. Save/load round trip and About did not pass.

File-type dropdown observations after harness stopped:
- Click702,545 focused combo100013; no visible expanded list appeared.
- Alt+Down positioned list100014 at398,556..713,586. List remained invisible;
  X image readback reported error8.
- Down,Enter changed Text files to All files. Keyboard selection reached the
  control; this is NOT proof of visible popup or working mouse selection.
- Encoding input was attempted after VM exit and never reached the guest.
  /tmp/B3630-desktop-encoding.png is a stale prior screenshot; do not use it.

VM exited status0 at1789047577.5589137. No shutdown/reboot was issued here;
exit cause is unknown. No QEMU process was present at handoff.

## Confirmed invisible-dropdown defect and committed repair

KI0927; claimce1380c8e, runtime d34481ec3.
Combo initialization creates ComboLBox as a child, then calls SetParent to move
it to desktop. Actual tree_api::set_parent_for_current changed WindowManager
only. The compositor X window remained a child of the original combo, clipped
inside it. Source inspection identified the missing native reparent operation.

Repair adds bridge opcode9: native-parent HWND64 (zero desktop), then Rect16.
Actual SetParent publishes after canonical mutation and releasing GUI ownership.
Backend sends checked X reparent, retains the existing XID/surface/descendants,
updates presentation parent and ignores older configure notifications.
No new Windows parent registry. Canonical parent differs from transient owner.

Key files:
- crates/kernel/syscalls/src/nt_window/families/tree_api.rs
- crates/kernel/syscalls/src/nt_window/bridge.rs
- crates/kernel/syscall/src/nt_compositor.rs
- userspace/probes/windows-compositor/src/protocol.rs
- userspace/probes/windows-compositor/src/x11/reparent.rs
- docs/31gd-windows-compositor-bridge.md
- scratch/B3630-reparent-validation.md

This reparent repair has NOT run in the guest.

## Final snapshot correction

The final correction after d34481ec3 affects:
- crates/kernel/syscalls/src/nt_window/bridge.rs
- crates/kernel/syscalls/src/nt_window/bridge/tests/reparent.rs

The first implementation widened shared Snapshot with tree_parent. x86 static
stack comparison found18 existing GUI paths increased16bytes each.334 reported
paths remained, but the growth is real and must not be called unchanged.

Final correction removes the extra shared Snapshot field. Reparent builds
its parent payload directly from canonical state only in its own publication
path. Other snapshot users retain the previous structure size. The canonical
payload regression passes after this correction; log
/tmp/B3630-reparent-payload-small.log.

Final target builds/frame/static comparison for this correction are outstanding.
Do not discard the correction or claim stack growth resolved before measuring.

## Tests completed for reparent repair

- Actual production SetParent hook fixture passes. Hosted seams supply caller,
  access and publication; real WindowManager changes parent. Removing the
  publication call causes intended assertion failure, restored passes.
- Real-X-server bridge regression verifies server parentage, visible retained
  pixels outside old parent, same XID, reparent-back, unknown-parent rejection
  and native BadWindow failure. Removing X reparent causes intended failure.
- Compositor library101tests pass. Both native release builds pass.
- Syscalls library3277tests pass; ABI library304pass,1existing ignored.
- Canonical snapshot and malformed reparent codec tests pass.
- Both kernel target checks passed before the final Snapshot correction.
- x86 release and frame gate passed before correction; static growth above.

Logs: /tmp/B3630-reparent-{backend-final,backend-red,hook-green,hook-red,
payload,codec,syscalls,syscall-abi,check-x86,check-arm,native-x86,native-arm}.log.
Native hashes:
x86 36e794e362a604a0c858719bebd7c78515cde5ba3018139e0870f020009c5d21
ARM dd2b85cdecf5ca69c0494e8b4cae9543f55fe50ac64d4ec4e01a5482b4df4660

## Running jobs at interruption

- Session88034: make -j2 frame-gate stack-gate;
  /tmp/B3630-reparent-stack.log. x86 completed; ARM release linking at last read.
  This invocation spans the Snapshot correction; not a clean final verification.
- Session82244: push with documented KI0019 exceptions;
  /tmp/B3630-reparent-push.log. Hosted gate passed; feature checks were waiting
  for build lock. Verify terminal status and remote ref before claiming push.
- Session34958: payload-small test; log reports1pass, terminal may need polling.

Do not blindly relaunch jobs. Check processes and these logs first.
Existing baseline logs: /tmp/B3630-desktop-bootstrap-stack.log and
/tmp/B3630-desktop-bootstrap-stack-arm.log. Baseline334x86/277ARM paths,
exception7664/6368. Compare all primary NEW rows by name and bytes.
If make stops before ARM frame/static commands, use repository policy values:
ARM stack --arch aarch64 --fail13000 --entry-fail6100, with allowlist and
entry/indirect maps from Makefile. Do not use the wrong8192/6144 thresholds.

## Next work, if user resumes

1. Finish/poll current jobs; preserve and commit corrected reparent snapshot.
2. Run final both-architecture build/features/frame/static checks. Resolve any
   added/increased stack paths; record honest results and verify remote push.
3. Fresh image helper /tmp/B3630-reparent-verification.py exists but has NOT
   prepared or booted an image. It is cloned from prior verification helper.
   Verify staged kernel/native hashes before using it. No VM currently runs.
4. Guest verification must show dropdown list, mouse item selection, keyboard
   selection and repaint, plus encoding. The harness currently only opens and
   dismisses file-type lists; selection/encoding acceptance still needs work.
5. Diagnose remaining dialog decoration/stripe/file-list failures from retained
   evidence. Do not call normal filename height or keyboard selection completion.

## Evidence and remaining issues

Latest guest: target/B3630-desktop-verification-debug/live.json and
uart-4192767.log. Screenshots /tmp/B3630-desktop-{initial,open,dropdown,
dropdown-key,selected}.png. Probe /tmp/B3630-desktop-probe.log exit0.
Guest kernel e04ec52945893be256529255aa7b4345c695b2d2f268d30698617832998a6681.
Guest ISO69f01dad499311c11dd1b7f0e47f2a6c00a0ee3e1e074e825c1b56c0015bcf82.
These images predate reparent repair.

KI0925 closed795fcf64b: exact segmented menu OCR repaired underlined File/Eile
misread. Real screenshot RED before,19adjacent tests pass, actual File/Open
harness clicks pass. It does not bypass the document or dialog checks.
KI0926 native measurement trace still unobserved despite launch flag; raw DC
trace works. Do not claim native measurement instrumentation executed.
KI0928 OPEN, documented5789e8b18: SetParent still lacks full hide/show/position
callback sequencing, explicit desktop/message-parent normalization and foreign
thread dispatch. KI0927 is native reparent publication, not full API compliance.
KI0923 combo acceptance, KI0887 paint acceptance and KI0863 full dialog harness
remain open. Earlier shared paint b1a9c0feb and compositor replay18869d93e are
recorded in their scratch validation files; they did not complete Notepad.
ARM Windows PE callback/execution gaps remain; native/kernel ARM builds are not
ARM Notepad acceptance. Related rows KI0699/0703/0704, sysroot KI0421/KI0691.

Do not edit main, stash, reset, amend, format or blanket-stage. Commit hooks
require tracked edits staged, so do not accidentally bundle this handoff with
unfinished runtime changes. This handoff is included in the user-authorized commit and merge.
