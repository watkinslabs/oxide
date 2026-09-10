# Parent and child retained drawing

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI-0921 native image replay |

Production `Backend::present` now retains parent drawing in existing visible descendant images; Show/Expose/caret restoration clips children. Actual ConfigureNotify geometry supplies descendant offsets. No additional persistent window state.

Real Xvfb suite: 110 tests passed (100 library, 2 caret, 1 input, 7 server damage). Four independent controls fail their intended pixel assertions: replay with IncludeInferiors, omitted descendant retention, hidden-branch writes, ignored reported child position. Restored suite passes. Logs `/tmp/B3630-parent-replay-suite.log`, `/tmp/B3630-parent-replay-control-{replay-mode,child-retention,hidden-child,reported-position}.log`.

Release compositor builds passed for x86_64 and aarch64; logs `/tmp/B3630-retention-build-{x86,arm}.log`. Existing 23 dead-code warnings unchanged. ARM host sysroot lacked dependencies (KI-0691/KI-0421): installed cached Fedora42 aarch64 libxcb1.17.0-5, libxkbcommon and libxkbcommon-x11 1.8.1-1, libXau1.0.12-2, libgcc15.2.1-7. GCC package supplies its original libgcc_s linker script, exposed through usr/lib64/libgcc_s.so in the same sysroot. No source or compiler flags changed. These host setup issues remain open pending reproducible provisioning.

Live verification pending against preserved QEMU3672245; old compositor still produced blank Open dialog. Hosted pixel checks alone do not establish Notepad acceptance.
