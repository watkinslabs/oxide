# Handoff — Notepad dropdown reparent repair in progress

First command: `git status --short`
Worktree /home/nd/oxide/kernel-B3630, branch B3630-paint-region-collapse.
Read CLAUDE.md and scratch/B3630-reparent-validation.md before editing.
Main read-only afa38ce09. Draft PR7680; do not merge or mark full goal complete.
User requires defect-free Notepad borders/buttons/Open/Save/About/dropdowns.
Consult actual Wine11.16 source ../windows_reference/wine-source and Linux ../reference.
Wine release/debug profiles explicit; do not fork/patch runtime source/catalog.

## Current source

- KI0927 claimedce1380c8e. Reparent runtime/tests/spec repair ready for source commit.
  Actual SetParent only mutated WindowManager; ComboLBox remained native child
  clipped inside its original combo after canonical move to desktop.
  New opcode9 carries native-parent HWND64 plus Rect16; zero means desktop.
  Existing XID/retained surface preserved by checked X reparent, no shadow owner.
  tree_api publishes after GUI unlock. Real-X-server test and actual hook test
  pass; deleting X request/publication produces intended RED. Backend101PASS.
  Snapshot/codec tests, both target checks,3277syscalls and both native buildsPASS.
  Kernel release/frame/static running session88034; logs /tmp/B3630-reparent-*.
  Required next: finish tests, both native builds, both kernel builds/features/
  frame gates; compare static paths versus334x86/277ARM baseline, KI0019.
  Backend regression covers retained pixels and native/unknown-parent refusals.
- KI0924 ca07ea578 FIXED: namespace lacked permanent WindowStations parent.
  Actual bootstrap path test RED ParentMissing then4PASS,104objects/2029schedPASS.
  Both builds/features/frame PASS, static334/277 unchanged, exceptions7664/6368.
- KI0925 795fcf64b FIXED: segmented exact menu OCR recovers underlined File.
  Real screenshot RED before,2testsGREEN,19adjacentPASS, actualguest initial-token
  and File/Open clicksPASS. Both fix ledger closures currently uncommitted.
- Source/push remote last verified795fcf64b. ce1380c8e not yet pushed.
  Push exceptions only SKIP_LINT_RATCHET=1 SKIP_TEST_BUILD_GATE=1 SKIP_STACK_GATE=1
  per KI0019; hosted/features mandatory. PR body /tmp/B3630-pr-body.md needs update.

## Guest evidence

- No VM live. Latest4192826 exited0 at1789047577.5589137 without issued shutdown.
  Runner87874; helper /tmp/B3630-desktop-verification.py prepare|run.
  target/B3630-desktop-verification-debug/live.json and uart-4192767.log.
  Single Notepad start54.219tid13c6; screenDCs nowNONZERO.
  Filename edit height15px, readable *.txt. DiagnosticPE /tmp/B3630-desktop-probe.log
  exits0; previousnamespace image exited7. Sourceprobe scratch/B3630-dc-probe/.
  Initialtoken and File/Open pass, dialog decoration checkFAIL: severe stripes,
  missing title/chrome, black/blank filelist. Full Save/About unverified.
- Measured arrow click702,545 focuses file-type combo100013; no visible list.
  Alt+Down positions list100014398,556..713,586; XGetImage fails8, invisible.
  Down+Enter changes Text files->All files. Selection reaches control;
  native reparent missing as above. Encoding NOT tested before VM exited.
- Images /tmp/B3630-desktop-{initial,open,dropdown,dropdown-key,selected}.png.
  /tmp/B3630-desktop-encoding.png is STALE previous screenshot; NOT evidence.
  Failed encoding scripts used unavailable QMP after VM exit; no input occurred.
- Stagedkernel e04ec52945893be256529255aa7b4345c695b2d2f268d30698617832998a6681.
  ISO69f01dad499311c11dd1b7f0e47f2a6c00a0ee3e1e074e825c1b56c0015bcf82.
  Wine11.16debug stamp000982e8e976863f0a29925ab7426d09808a3e61c125c18decc4cf77f27af5da.
  Predates reparent repair. Native trace KI0926 unobserved; rawDC trace works.

## Earlier repairs and open scope

- KI0922 b1a9c0feb shared containing paint backings;1560IPC/3276syscalls/
  278boundary testsPASS,3controlsRED; both builds/features/framePASS. KI0887
  full paint/border/dialog acceptance remains open. scratch/B3630-shared-paint-validation.md.
- KI0921 18869d93e compositor parent draw versus retained replay;110tests then,
  4controlsRED; both nativebuilds. scratch/B3630-parent-replay-verification.md.
- KI0920 598ecf668 mouse parking repaired; pointer stays at clicked target
  through observation. X RECORD proved immediate parking moved releaseoutside.
- KI0863 dialog harness lacks actual selection/encoding/popup geometry checks;
  currently opens file-type dropdown and Esc only. Must complete acceptance.
- KI0885 full scrollbar pointer tracking/setters/accessibility, KI0904
  EnableWindow callbacks, KI0398 bitmap caret, KI0917 quit filtering remain.
- ARM Windows PE execution/callback gaps KI0699/0703/0704 remain; native/kernel
  ARM builds do not establish ARM Notepad guest acceptance.
- native ARM .cargo/config.toml uses Fedora sysroot; run builds from userspace/probes.
  Existing system sysroot provisioned cached packages; KI0421/KI0691 remain.
- packages branchB3630-wine-profiles6830f27; images553217b; no remotes.
  Preserve images .dist-old-layout. Main tree untouched.
- Never fmt/stash/reset/amend/blanket stage. Stage named files; commit hooks
  require all tracked edits staged. Current root worktree clean outside lane.
