# C294 — the hosted-global-state defect is now audited, not discovered

`B1949` (net), `B1955` (nscg), `B1956` (security) and `B1957` (socket) are one
defect found four times by accident, each after it had flaked for months. The
precondition is grep-able; `tools/hosted-global-audit.py` greps it, answers the
one question that separates a fixed crate from a flake waiting to happen, and
runs as `make hosted-global-gate` so occurrence five fails at PR time.

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED C294 | COVERAGE | high | Nothing in the tree could detect the class that produced four incidents. Each was found by a flake, then diagnosed from scratch; the audit surface was never enumerated, so the count of exposed tests was only ever learned by breaking something (2 visible / 70 exposed in `B1949`; 3 attributed / 16 failing / 23 exposed in `B1957`). | `make hosted-global-gate`: 887 candidates, 16 guarded, 438 claimed by every test in their binary, **433 unguarded** and recorded in `tools/hosted-global-state-backlog.tsv`. The gate fails on a new unguarded candidate and on a backlog row whose candidate has since been guarded, so the backlog can only shrink. | Chris Watkins |
| OPEN | COVERAGE | high | 433 unguarded candidates, 59 of them bare serialisation locks — `B1957` predicted 25 from a narrower grep, and every one of those 25 is in this list. Each is a fixture lock whose protection is a convention any new test in the same binary can forget. | `tools/hosted-global-state-backlog.tsv`, one row per candidate, sortable by claim ratio. The worst by exposure: `net/src/net_ns/test_support.rs::LIFETIME_LOCK` (17 of 2186 tests in the binary claim it), `sched/src/tests/timing.rs::SERIAL` (1 of 1210), `fs/src/timerfd/tests.rs::TEST_LOCK` (10 of 1002), `syscalls/src/fcntl_dup_tests.rs::TEST_LOCK` (2 of 1329). | unassigned — one row per lane |
| OPEN | COVERAGE | med | `crng/src/pool/tests.rs::SOURCE_LOCK` states the requirement in its own doc comment — "`BULK_SOURCE` and `SEEDED` are process-global, so every test that installs a source or inspects readiness must run alone" — and 12 of the crate's 17 tests call `fill()`, which reads both, without it. Exactly the `B1957` shape: the lock protects the fixture, not the state the fixture installs into. | Flagged `UNGUARDED fixture-lock crng/src/pool/tests.rs:22 SOURCE_LOCK [5/17 tests claim]`. Not observed to fail — structural, not measured. | unassigned |
| OPEN | COVERAGE | med | `modules/src/test_serial.rs::MODULES` (217/231), `drv/src/model/test_claim.rs::MODEL` (38/40), `fbdev/src/test_claim.rs::FBDEV` (27/30), `input/src/tests.rs::TEST_MUTEX` (18/22), `ucounts/src/tests.rs::LOCK` (11/12): near-total conventions, which is the state `socket` was in before the 18 non-claiming tests were noticed. A convention at 94 % is one added test away from the flake. | Same file; claim ratios above. | unassigned |
| OPEN | COVERAGE | med | 65 `singleton-pin` rows: hosted fixtures pinning a process-global singleton through a parameterless accessor (`vfs::initial`, `drv::devices`, `network-namespace::initial`, `devfs::clear_hwrng_source`, …). `B1957` names de-pinning as the only lever that removes the class rather than guarding it — these rows are the inventory for that work. | `tools/hosted-global-state-backlog.tsv`, rule `singleton-pin`. | unassigned |
| FIXED C294 | INFRA | low | `hosted-selection` (the `B1956` defect: storage chosen by `test`/feature rather than by target, so a downstream crate that omits the feature compiles the per-CPU array into a hosted build) has **zero** occurrences in the tree today. The rule is kept because the shape is invisible from the owning crate's own tests, and its self-test mutant plus a target-selected green control prove the check can fail. | `--self-test` mutant `hosted-selection`; green control `green-target-selected-global`. | Chris Watkins |

## What the tool decides, and how

Four rules, each with its own diagnostic so one cannot pass as another's control:

| Rule | Candidate |
|---|---|
| `fixture-lock` | test-declared static `Mutex<()>`/`RwLock<()>` — a pure serialisation lock |
| `fixture-state` | test-declared static carrying a payload: mock records, counters, installed hooks |
| `singleton-pin` | test code calling a parameterless production accessor over module-global state |
| `hosted-selection` | one global with two cfg-selected definitions where the discriminant is `test`/a feature rather than the target |

**"Guarded" is read out of the source, not a list.** A crate that has been fixed
carries the structure the three fixes converged on: a claim module holding a
per-thread depth `Cell` raised on acquire and lowered in `Drop`, plus an
`assert_*` that reads it. That module counts as a guard only once the assertion
is **called from a file that is not itself test-only** — i.e. from the choke
point on the ordinary path, the one place a forgetful test cannot avoid. There
is no hand-maintained roster of blessed choke points, because a second list is a
second thing to forget. The check correctly and independently identifies all
five locks the three fixed crates own (`net::INITIAL_NET_DOMAIN`,
`net::PACKET_RING_DOMAIN`, `nscg::REGISTRY`, `socket::POLICY`, `socket::SCM`)
and refuses a claim module whose assertion nothing calls.

**Exposure is `claimants / tests in the same binary`.** A candidate is reported
only when some test in its binary does *not* reference the owner module — which
is precisely the `B1949`/`B1957` discriminator (70 and 18 non-claimants). Where
every test in the binary claims, the convention currently holds and the row is
not raised; the moment a test is added that does not claim, it becomes a new
backlog row and the gate fails. That is the occurrence-five case.

**Excluded, with reasons.** `thread_local!` storage (per OS thread — the fix,
not the defect), and initialise-once statics whose payload carries no interior
mutability (every observer gets the same value, so nothing crosses tests).

## The backlog is a claim list, not an allowlist

`tools/hosted-global-state-backlog.tsv`, four tab-separated fields
(path, name, rule, reason). A row is permission for nothing: per CLAUDE.md the
defect is still work this project will do, and the gate refuses a row whose
reason field is empty and refuses a row whose candidate has since been guarded
(`is no longer unguarded -- delete the row so the backlog can only shrink`).
Fixing a candidate is therefore a two-line diff: the choke-point assertion, and
the deleted row.

## Verification

`make hosted-global-gate` runs the self-test then the audit.

**Self-test** — `hosted-global-audit: self-test PASS (8 isolated mutants, 3
green controls)`. Each mutant injects one defect into an otherwise clean
fixture crate and requires that defect's own diagnostic verbatim. Mutants:
`fixture-lock`, `fixture-state`, `singleton-pin`, `hosted-selection`,
`unenforced-claim-module` (a claim module whose assertion nothing calls must
NOT read as guarded), `stale-backlog-row`, `backlog-row-without-reason`,
`malformed-backlog-row`. Green controls: an enforced choke point, a
target-selected global, and a backlog row that still describes a live candidate.

**Detection proof on a real instance** (`crng`, applied in the worktree and
reverted, not committed):

| Step | Result |
|---|---|
| unmodified tree | `UNGUARDED fixture-lock crng/src/pool/tests.rs:22 SOURCE_LOCK [5/17 tests claim]` |
| add a `SOURCE_DEPTH` thread-local raised in `exclusive()`, an `assert_source_owned()`, and a `#[cfg(test)]` call to it at the top of `pool::fill` | `GUARDED fixture-lock crng/src/pool/tests.rs:22 SOURCE_LOCK`, plus `tools/hosted-global-state-backlog.tsv: crng/src/pool/tests.rs 'SOURCE_LOCK' (fixture-lock) is no longer unguarded -- delete the row` |
| reverted | back to `UNGUARDED`; gate green against the committed backlog |

No kernel code changed, so no boot was run — the diff is one Python tool, one
generated TSV, one Makefile target and this file, none of which is on the boot
path.

## What it cannot catch — read this before trusting a green run

- **Reachability is not proved.** "N tests in this binary do not reference the
  owner module" is exposure, not a race. Some of the 433 rows are tests that
  could never touch the state. The tool ranks; it does not decide.
- **The converse is worse: a claiming test is assumed safe.** Claim detection is
  a name match against the static and the functions in its file that touch it. A
  test that mentions the accessor but takes the claim on the wrong resource, or
  drops it early, reads as a claimant.
- **`claimants == exposure` is silence, not safety.** `socket` would have scored
  clean this way if its 18 non-claiming tests had happened to live in another
  binary. The rule only fires once someone forgets *within one binary*.
- **A guard is judged by shape, not by coverage.** One `assert_*` called from
  one non-test file marks the whole declaring module guarded. It cannot tell
  whether the assertion sits at the choke point every entry path crosses or at
  one of five — the `B1957` failure mode of asserting in the wrong place is
  invisible here. `net`'s namespace-0 interface table is exactly this gap:
  `B1957`'s open row notes `socket` reaches it with no claim, and `net`'s
  `#[cfg(test)]` choke point compiles out of `socket`'s binary.
- **Cross-binary state is out of scope entirely** — a file the tests write, a
  device node, anything outside the process.
- **Parsing is regex over text, not a syntax tree.** Macro-generated statics,
  `#[path]` module redirection, and `cfg` gating applied by a parent module
  declaration are not followed; a kernel-gated file is recognised by its own
  inner attribute or an enclosing `cfg` block in the same file.
- **`crates/` only** (~40 s over the tree). Nothing under `userspace/`,
  `tools/`, or `vendor/`.
