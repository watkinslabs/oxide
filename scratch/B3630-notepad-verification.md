# Notepad verification

| Status | Requirement | Evidence needed | Branch |
|---|---|---|---|
| In progress | About and push-button captions | Open About; visible OK/license captions; real button closes it; hosted causality check for defect | B3630-paint-region-collapse |
| In progress | Save As, Save, Open | Save new file, edit/save, New, reopen; edited token inside document crop | B3630-paint-region-collapse |
| In progress | File-type dropdowns and Cancel | Visible expanded filters in both dialogs; Cancel returns with document intact | B3630-paint-region-collapse |
| Open | Menu dropdowns | File, Edit, Format, View, Help render and dispatch correctly | B3630-paint-region-collapse |
| Open | Border redraw and moves | Move/resize/occlusion evidence; preserved contents; no drawing outside surface | B3630-paint-region-collapse |
| Open | Cross-architecture verification | Both kernel gates; both applicable runtime acceptance paths | B3630-paint-region-collapse |

Harness: `tools/notepad_dialogs.py`, called by `run_desktop_checks` before closing.
Offline: 23 Notepad tests pass. Positive controls: removing dialog call,
accepting title text as document content, accepting title as button caption
all turn the new tests red; restored green. No new boot yet.

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
