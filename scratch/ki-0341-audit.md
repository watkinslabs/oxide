# KI-0341 audit

Status | Branch | Finding
---|---|---
verified | feat/windows-protected-duplicate-20260905 | KI-0341 is already fixed in `origin/main`; this branch records the independent audit and executable evidence.

## 1

Reference behavior checked before conclusion:

- `DUPLICATE_CLOSE_SOURCE` requests source consumption only after the duplicate operation has succeeded.
- `HANDLE_FLAG_PROTECT_FROM_CLOSE` belongs to the individual handle, so a protected source must remain live when source consumption is attempted.
- A refused source close must not invalidate the newly published duplicate.

Current-tree owners match that contract:

- `NtHandleTable::close_duplicate_source` routes through the normal close transaction, which applies the canonical per-handle protection check.
- The duplicate is allocated before the optional source close; output-copy failure closes that duplicate and leaves the source untouched.
- A protected source close returns no removal, while the duplicate and source continue to resolve the same object.

## 2

Hosted evidence:

- `cargo test -q -p sched --lib nt_object::tests::duplicate_close_source_preserves_a_protected_source -- --nocapture --test-threads=1`: 1 passed, 0 failed.
- RED positive control: bypassing the canonical protection predicate made the focused test fail at its protected-source assertion (exit 101).
- Restored branch: the same focused test returned 1 passed, 0 failed.

No boot was run: this audit changes no boot-visible code; the decision and its regression are hosted scheduler tests.
