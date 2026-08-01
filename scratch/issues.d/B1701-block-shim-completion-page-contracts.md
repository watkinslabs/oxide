# B1701 — block shim: completion and page contracts

Root cause shared by all three curated rows: the module-facing block shim decided facts that belong
to Linux's contracts — how long a request lives, how big a page is, how long a registry publication
lasts — instead of taking those answers from the contract itself.

## Curated rows this closes

| Row (scratch/known_issues.md) | State |
|---|---|
| `blk_mq_end_request` re-dereferences `rq` after `end_io`, discards its return | FIXED |
| `bio_add_page` bounds `bi_size` with the BioOwner buffer, not the page | FIXED |
| `LinuxBlockAdapter` holds `disk: usize` with no ownership tie | FIXED |

## What changed

- `linux_block/contract.rs` (new, **no target gate**) owns the three decisions: `rq_owner_after_end_io`,
  `addable_bytes`, `release_needs_unregister`. 11 unit tests.
- `blk_mq_end_request` reads every field of the request BEFORE running `rq_end_io_fn`, acts on that
  callback's return value, and never dereferences the request afterwards. `RQ_END_IO_FREE` (and the
  no-callback case) frees here; `RQ_END_IO_NONE` leaves the request wholly to the callback.
- The `complete` op moved out of `blk_mq_end_request` into a new exported `blk_mq_complete_request`,
  which is the entry point that owns it. Ending a request no longer dispatches `complete`.
- `blk_execute_rq` installs its own completion and reports the status that completion carried. It does
  not read the request back.
- `RqEndIoFn` gained its third `io_comp_batch` parameter; the return type is now the `rq_end_io_ret`
  value (`RQ_END_IO_NONE`/`RQ_END_IO_FREE` in `types.rs`), not a discarded `i32`.
- `bio_add_page` derives its bound from the page (`linux_alloc::page_run_len`, new) when the descriptor
  resolves, and from the bounce buffer only in the fallback arm. All-or-nothing, like Linux.
- `put_disk` withdraws the block-registry publication before freeing the gendisk.
- `linux_block/core.rs` (524 lines) and `mq.rs` (586) split into `core/{queue,disk,bio,adapter,tests}`
  and `mq/{queue,request,bio,status,tests}`; every file is now under the 500-line cutoff.

## Positive-control evidence

Each defect reinstated in isolation, then restored:

| Defect reinstated | Result |
|---|---|
| `blk_mq_end_request` discards the `end_io` return + re-derefs `rq` | 2 tests FAIL, 1 **SIGSEGV** (`end_io_none_leaves_the_request_untouched_after_the_callback` — the actual use-after-free) |
| `blk_execute_rq` re-reads `(*rq).status` after completion | `execute_rq_reports_the_completion_status_not_a_later_read` FAILS (left 0, right 10) |
| `bio_add_page` bounds by `owner.buf.len()` | 2 tests FAIL (left 1024, right 4096; left 1024, right 0) |
| `put_disk` skips the unregister | `put_disk_withdraws_the_registry_publication` FAILS |

Restored tree is byte-identical to the fixed tree and all 22 `linux_block` tests pass.

## New / remaining gaps found on the way (not curated rows)

| Sev | Finding | Evidence |
|---|---|---|
| med | `blk_execute_rq` has no wait primitive. It is synchronous for every completion path this shim drives, but a driver whose `queue_rq` completes asynchronously would return before the completion runs. That case returns `BLK_STS_IOERR` and deliberately leaks the small `SyncWait` record rather than leave the driver's `end_io_data` dangling. A real wait (completion + sleep) is the correct fix. | `mq/request.rs`, the `if !done` arm. No in-tree caller exercises it. |
| low | `bio_add_page`'s fallback arm (page descriptor does not resolve) silently ignores `off` and points the bio at the owner's bounce buffer from offset 0. The bound is now honest, but the data is not the caller's page. The shim's `LinuxBio` has no `bi_io_vec` array, so it cannot represent a real multi-page bio at all. | `core/bio.rs`, the `page_data.is_null()` arm. |
| low | `bio_add_page` is now all-or-nothing (Linux semantics). A module that previously got a truncated count from the bounce-buffer arm now gets 0. That is the correct answer — a truncated count read as a completed add is the bug — but it is a behaviour change for any caller that tolerated the truncation. | `core/tests.rs::bio_add_page_without_a_page_is_bounded_by_the_bounce_buffer` |
| low | `blk_mq_end_request_batch` is still a no-op, so a driver using `io_comp_batch` never completes its requests. Pre-existing; not touched here. | `mq/request.rs` |
