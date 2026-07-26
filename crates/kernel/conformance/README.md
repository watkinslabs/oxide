# conformance — F721 host-oracle differential syscall harness

Answers "does our syscall behave like Linux?" by RUNNING each case on the
host Linux kernel (the oracle — this machine's own `libc`/`syscall(2)`) and
on the oxide work-fn crate that implements the same behavior, then
comparing. Never hand-write an expected errno from memory (`docs/15`).

## Layout

- `src/oracle.rs` — host-side wrappers (`open`, `mkdir`, `dup3`, `pipe2`, …),
  each returning an [`outcome::Outcome`] (return value + errno, decoded from
  the real `errno` global after a `-1` return).
- `src/outcome.rs` — the shared `Outcome` type + `same_errno_class` (success
  class must match; on failure, the errno must match). `ret` is compared too
  ONLY when a case opts in (`Case::compare_ret_on_success`) — fd numbers,
  inode-adjacent counters etc. never line up across two independent kernels.
- `src/corpus.rs` — `Case` (one corpus row) + `run_corpus` (the one call
  each test file's `#[test]` makes).
- The actual corpus tables live NEXT TO the oxide code they exercise, one
  file per syscall family, e.g. `crates/kernel/vfs/tests/conformance_fd.rs`,
  `conformance_path.rs`, `conformance_misc.rs`. Put a new family's corpus in
  the crate that owns the real work-fn (`vfs`, `fs`, `sched`, `ipc`, `net`,
  per `docs/53` layering) — this crate stays host-only infra, never itself
  wired into a `vfs`/`fs`/… dependency.

## Adding a case (one line)

1. Write a `fn my_case() -> (Outcome, Outcome)` that:
   - drives the HOST side via `conformance::oracle::*` (add a new oracle
     wrapper if the syscall isn't covered yet — same shape as the existing
     ones: real `libc` call, `Outcome::from_host(ret)`);
   - drives the OXIDE side by calling the REAL work-fn. Prefer the
     crate's own ungated public API (e.g. `vfs::namei::may_delete`,
     `vfs::FdTable::dup3`) over reimplementing logic. If the only real
     entry point sits behind `#[cfg(target_os = "oxide-kernel")]`
     (`crates/kernel/syscalls/src/*`), pull the file in verbatim via
     `#[path]` (see `conformance_fd.rs`'s `fcntl_dup` include, or
     `conformance_misc.rs`'s `035_nanosleep`/`time_common` includes) rather
     than copying its logic by hand. Widening a bare `#![cfg(target_os =
     "oxide-kernel")]` to `any(target_os = "oxide-kernel", test)`, or a
     private `fn` to `pub(crate)`, is the established, low-risk way to make
     a real file reachable hosted — it changes nothing at runtime. Document
     which you did and why in the case's doc-comment.
2. Add one row to the file's `CASES` table:
   `Case { id: "family.case_name", known_divergence: None, skip: None,
   compare_ret_on_success: false, run: my_case }`.
3. `cargo test -p <crate> --test conformance_<family>` — green means match;
   a panic means `run_corpus` found a NEW divergence and printed both sides'
   `Outcome`s. Do not "fix" it by loosening the case — either it is a real
   defect (report it, and if you want the suite green while it's open, set
   `known_divergence: Some("<file:line + one-line defect description>")`)
   or the case/fixture itself was wrong (fix the case).
4. If the case cannot be run hosted at all (needs a resource this harness
   doesn't stand up — a live `Task`+scheduler, a whole-crate-gated
   dependency, two real separate mounts, …), set
   `skip: Some("<reason>")` instead of forcing it through. `run` is still a
   required field but is never called when `skip` is `Some`.

## Why this catches real divergences without QEMU

Everything under `crates/kernel/{vfs,fs,sched,ipc,net}` is the REAL,
`no_std`-compatible work-fn implementation (`docs/53`: the kernel's
`syscalls/` crate is a hollow ABI shim, all Linux semantics live one level
down). Most of that code has NO target-specific cfg gate — it is portable
by construction and already compiles and runs on the host under `cargo
test`. Only the thin syscall-entry shims (`crates/kernel/syscalls/src/*`)
are gated to `target_os = "oxide-kernel"`, because they read raw user
pointers (`uaccess`) and the live per-CPU scheduler — this harness drives
the REAL logic one layer down from there, which is exactly where the Linux
contract (error ordering, permission checks, resolution semantics) is
actually decided.
