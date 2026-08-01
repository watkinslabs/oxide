# C257-spec-lint-cfg-test-scope

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED C257 | high | `code/panic-fmt` reported 113 findings and **111 of them were test code**, not kernel code. The lint had no model of `cfg`, and unlike five sibling rules it was not even given the existing path-based `is_test_file` skip. Enforcing "no `panic!(fmt)`" inside `#[cfg(test)]` is incoherent on its face: every `assert_eq!` in the same test expands to exactly the formatted panic being forbidden. | `docs/07§5` states the rule for kernel profiles (`panic="abort"`, interned strings). Before/after: 113 → 2. The 2 survivors were real and are fixed in this PR. | C257 |
| FIXED C257 | high | `code/extern-std` reported 18 and **all 18 were false positives**. The guard looked at exactly one preceding non-blank line, so the ordinary form — `extern crate std;` a few lines into a `#[cfg(test)] mod tests { … }` — read as unguarded. `docs/07§5`'s own wording is "`extern crate std` in any kernel **binary** → fail"; none of these are in a kernel binary. | 16 sites inside `#[cfg(test)] mod tests`, `crates/kernel/ext4/src/lib.rs:21` under `#[cfg(not(target_os = "oxide-kernel"))]`, `crates/kernel/syscalls/src/lib.rs:280` under `#[cfg(all(test, not(target_os = …)))]`. 18 → 0. | C257 |
| FIXED C257 | med | `code/no-std` reported 2, both false positives. `crates/kernel/conformance` is the host-oracle differential harness, reachable ONLY through `[dev-dependencies]` (`syscalls`, `vfs`) and `std` by design. `crates/kernel/syscalls/src/054_setsockopt/main.rs` is a syscall SLOT module that the lint read as a crate root because `is_crate_root` tested the FILENAME alone. | Fixed by deriving scope, not by an allowlist: a crate root now requires `<crate>/src/lib.rs` with a real `Cargo.toml`, and dev-only crates are computed from the manifests' dependency KIND. 2 → 0. | C257 |
| FIXED C257 | med | `code/magic-errno`'s single finding in the entire tree was a false positive: `pub fn names_slot(&self, slot: usize) -> bool { self.qname_spec & (1 << slot) != 0 }`. The rule matched the marker `_slot` anywhere on the line — here inside the METHOD NAME — and paired it with the `!= 0` of an unrelated bitmask test. | `crates/kernel/ext4/src/mount_opts/ctx.rs:56`. Fixed by requiring the identifier immediately left of the operator to end with the marker. Test `a_marker_inside_an_unrelated_identifier_is_not_the_operand` reproduces the exact line. | C257 |
| FIXED C257 | med | While tightening `code/magic-errno` it turned out the rule was ALSO under-detecting, and had been since it was written: `trim_operand` stripped trailing punctuation off the whole remainder of the line, so `if info.signo == 17 { reap(); }` yielded the operand `17 { reap(` and passed. Any comparison followed by a block — the common shape — was invisible. `is_int_literal` accepted any run of `[0-9a-fx_]`, so the binding name `cx` parsed as an integer. | Both fixed (operand = first token; literal must start with a digit). Widening exposed 28 sites, 26 of which were `errno == 0` / `signo == 0` — the not-an-error sentinel the assignment branch already exempted, now exempted consistently. Net real findings: 0. | C257 |
| FIXED C257 | med | Two real `panic!("… {:?}", e)` in kernel boot code, on paths that run in every boot: `console::devnodes::register_devnodes` and `devfs::boot::populate_defaults`. Both drag `core::fmt` into an abort path that `docs/07§5` requires to use interned strings. | Replaced with a `#[cold] fn … -> !` matching the 8 `drv::Error` variants to per-variant literals, so the abort message keeps the error detail without a format string. | C257 |
| FIXED C257 | low | `docs/MANIFEST.md` listed `kernel-audit.md` and `network-gap-analysis.md`, both deleted (`3643d52c2`, `b5e48071b`) — `MANIFEST` is declared authoritative by CLAUDE.md and had been wrong since those deletions. | `manifest/dangling` ×2 → 0. Rows removed. | C257 |
| FIXED C257 | low | `docs/60-udev-kernel-contract.md:10` cited `19§Purpose`; `docs/19` numbers its sections, so the target is `19§1`. | `xref/sec` 1 → 0. | C257 |
| OPEN | med | `docs/00-master-plan.md:260`, `docs/43-acceptance.md:76` and `docs/40-ci.md:46` all make a RELEASE GATE out of "Kernel-completeness audit `docs/kernel-audit.md` shows no stub regressions" — and that file was deleted in `3643d52c2` (July 2026). Three release gates cite a document that does not exist, so the gate cannot be evaluated and has silently been vacuous. spec-lint does not check file-path citations inside prose, only `<doc>§<sec>` refs, which is why it never surfaced. | `git log --diff-filter=D -- docs/kernel-audit.md`. Not fixed here: choosing the replacement gate (or dropping it) is a spec decision, not a lint lane's call. | — |
| OPEN | low | `code/klog-ungated` treats `klog::kfatal!` and `klog::kerror!` as requiring a `debug-<sub>` feature gate, the same as `kdebug!`. A fatal or error log that only exists in a debug build is not a diagnostic anyone will have when it matters, and it makes "log the detail, then abort with a literal" — the natural fix for `code/panic-fmt` — cost a new finding. | `tools/spec-lint/src/code_lint/klog.rs:74-80` lists all five macros in one `MAC_NAMES` table. Worth deciding before the 625-finding `klog-ungated` backlog is worked. | — |

## Counts (whole tree, `cargo run -p spec-lint -- all`)

| Rule | Before (C255 baseline) | After |
|---|---|---|
| `code/pub-fn-complexity` | 1223 | 1143 |
| `code/safety-missing` | 652 | 643 |
| `code/klog-ungated` | 625 | 625 |
| `code/panic-fmt` | 113 | 0 |
| `code/safety-short` | 58 | 56 |
| `code/extern-std` | 18 | 0 |
| `manifest/dangling` | 2 | 0 |
| `code/no-std` | 2 | 0 |
| `xref/sec` | 1 | 0 |
| `code/magic-errno` | 1 | 0 |
| `len/over-cap` | 1 | 1 (B1690 lane) |
| **total** | **2696** | **2468** |

The `pub-fn-complexity` / `safety-missing` / `safety-short` movement is not a
rule change: it is `crates/kernel/conformance` (dev-only) plus the two
directory-backed `#[cfg(test)] mod` subtrees leaving scope. The `safety` rules
are deliberately NOT given the inline `cfg(test)` exemption — an `unsafe` block
is unsound or not regardless of who links it.
