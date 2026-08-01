# C259-ratchet-tighten-baseline

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED C259 | high | The ratchet treated slack below the baseline as a NOTE, so four merged burndown PRs (#4394, #4397, #4399, #4402) left **379 fixed findings unlocked**. Any of them could be reintroduced and the gate would stay green — a ratchet that is never tightened is only a high-water mark. Tightening was documented as a convention (`make lint-ratchet-update`) and, being a convention, was not done by any of the four. | `make lint-ratchet` on `0422edebe` printed `PASS — 379 finding(s) below baseline`, exit 0. Slack is now a FAIL naming the exact command. The baseline tightening itself landed first, in #4403 (2468 → 1942, which subsumes the 2089 this PR originally carried); what remains here is the gate change that makes tightening mandatory. | C259 |
| FIXED C259 | high | Concretely what was unlocked: `crates/kernel/modules code/safety-missing` stood at **336** in the baseline while the crate's real count was **0** after #4402. 336 missing-SAFETY blocks could have come back without the gate noticing. | Positive control below. The key is now ABSENT from the baseline, which compares as 0, so reintroducing a single `unsafe { }` without a SAFETY comment fails. | C259 |
| NOTE | info | A key whose count reaches zero DROPS OUT of `baseline.tsv` rather than being stored as `0`. That is TIGHTER, not coverage loss: a missing key compares as 0, so a reintroduced finding under it is a regression. Do not "helpfully" re-add dropped keys as explicit `0` rows — reading a shrinking baseline as lost coverage is the mistake this row exists to prevent. | `ratchet.rs:92` — "Absent from baseline = 0, so a brand-new unit or rule is a regression." After #4403, `crates/kernel/modules code/safety-missing` and `crates/user/glibc code/safety-missing` are gone from the file for exactly this reason. | C259 |
| OPEN | med | `code/safety-missing` scans only 4 lines back for the `// SAFETY:` marker, so a SAFETY statement heading a longer explanatory comment reads as missing. Lane B1693 hit this on 12 of its 147 blocks and worked around it by putting the SAFETY sentence LAST — i.e. the lint is currently shaping comment layout rather than checking comment content. That layout was reviewed and kept on its merits (rationale first, safety claim at the point it applies), but it was chosen under lint pressure, which is the distortion this row names. | Reported by B1693 (`scratch/issues.d/B1693-safety-comments-kernel-core.md`). Not fixed here: it changes counts, so it belongs in its own PR with its own tightened baseline rather than mixed into a baseline-only change. | spec-lint lane |
| FIXED #4403 | low | Two open safety PRs (#4403 kernel-core, and the virtio/drm lane) were cut before this change and carried the untightened baseline. Each needs a `make lint-ratchet-update` commit before merge, or it merges slack straight back in. | #4403 tightened 2468 → 1942 on its own branch before merging and now reads `PASS — at baseline`. The virtio/drm lane still owes its own tightening commit. | integration owner |

## Positive control

Against the **untightened** baseline on `origin/main`:

    crates/kernel/modules	code/safety-missing	336      # real count: 0

so reintroducing a missing-SAFETY block anywhere in that crate was a no-op for the
gate. After tightening, the key is absent — which compares as 0 — and appending

    pub fn pc_reintroduced(p: *mut u8) { unsafe { core::ptr::write(p, 0); } }

to `crates/kernel/modules/src/linux_alloc.rs` produces, exit 1:

    REGRESSION crates/kernel/modules [code/pub-fn-complexity] 36 > 35 (baseline)
    REGRESSION crates/kernel/modules [code/safety-missing] 1 > 0 (baseline)

Reverting returns `PASS — at baseline`.

Staleness itself is covered by a unit test rather than by this one-off:
`slack_below_the_baseline_fails_until_it_is_tightened` asserts FAIL at 380-vs-500,
PASS after `--update`, and that the stored baseline then equals the current counts.
