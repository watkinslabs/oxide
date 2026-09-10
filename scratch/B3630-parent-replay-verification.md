# Parent and child retained drawing

| Status | Branch | Item |
|---|---|---|
| FIXED | B3630-paint-region-collapse | KI-0921 native image replay |

Production `Backend::present` now retains parent drawing in existing visible descendant images; Show/Expose/caret restoration clips children. Actual ConfigureNotify geometry supplies descendant offsets. No additional persistent window state.

Real Xvfb suite: 110 tests passed (100 library, 2 caret, 1 input, 7 server damage). Four independent controls fail their intended pixel assertions: replay with IncludeInferiors, omitted descendant retention, hidden-branch writes, ignored reported child position. Restored suite passes. Logs `/tmp/B3630-parent-replay-suite.log`, `/tmp/B3630-parent-replay-control-{replay-mode,child-retention,hidden-child,reported-position}.log`.

Release compositor builds passed for x86_64 and aarch64; logs `/tmp/B3630-retention-build-{x86,arm}.log`. Existing 23 dead-code warnings unchanged. ARM host sysroot lacked dependencies (KI-0691/KI-0421): installed cached Fedora42 aarch64 libxcb1.17.0-5, libxkbcommon and libxkbcommon-x11 1.8.1-1, libXau1.0.12-2, libgcc15.2.1-7. GCC package supplies its original libgcc_s linker script, exposed through usr/lib64/libgcc_s.so in the same sysroot. No source or compiler flags changed. These host setup issues remain open pending reproducible provisioning.

Live verification: preserved QEMU3672245, normal wrapper1401/Notepad1418/compositor1421, loaded ELF SHA256 b4c0536a005117b1977495d656836757dc4dbd307a12d3b3287578e01301cc34 matches host build. Previous task-owned instance951 reached save prompt but No/Alt-N did not dismiss; TERM after preserving token-only document evidence. No VM restart. New instance draws token/edit area and File popup; Open still lacks labels/buttons (Look-in combo survives). Title decoration absent and desktop fragments persist. Acceptance failed initial title-based document check; manual measured File/Open clicks separately created dialog. Evidence screen-3878087-before-compositor-replace.ppm, /tmp/B3630-retention-accept.log, /tmp/B3630-repaired-xtree.log; per-launch guest windows-launch-debug-1401.log. KI0887 remains open; replay repair alone does not establish Notepad acceptance.
