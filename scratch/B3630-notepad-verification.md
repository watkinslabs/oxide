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
