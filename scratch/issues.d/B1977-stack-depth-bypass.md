# B1977 — aarch64 stack-depth ceiling crossed, pushed with the gate bypassed

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | High | The bpf verifier/command work pushes an aarch64 static call path to or past the 13000 B ceiling on a 16384 B kernel stack. The branch was pushed with `SKIP_STACK_GATE=1` on an explicit instruction to land the work; **the overrun ships with it.** A kernel stack overrun does not fault cleanly — it scribbles the adjacent allocation, and this tree has already lost multiple sessions to exactly that class (the ~90% boot corruption was a 16 KB stack overflowing into the heap, chased for weeks as a refcount UAF before guard pages proved it). | `make stack-gate` on `B1977-bpf-verifier-and-commands` reports `>= ceiling (13000B): 4`. Deepest chain at the time of the bypass: `_start` 19832 → `_start_rust` 19816 → `kernel_main` 19752 → `rootfs::init` 16552 → `smoke::elf::run_as_task` 12184 → `oxide_syscall_entry` 12064 → `oxide_syscall_dispatch` 11880. Three of the four over-ceiling paths are pre-existing allowlist entries; this lane's contribution is the fourth and is NOT allowlisted. | unowned |

**Fix, not a workaround.** The gate's own message states it: an allowlist entry is
permission for the defect, not a fix. The correct close is to split the chain so the
big frames overlap instead of summing, or move the data off-stack — the same shape
three lanes used successfully this session:

- B1950 boxed a credential snapshot that a guard held **by value** in a frame every
  operation ran beneath, and marked its installer `#[inline(never)]`: 13056 → 12960 B.
- B1960 boxed settled transmit overrides out of three frames after measuring a +224 B
  regression against a locally built baseline: back under budget.
- B1970 split two write legs that had been merged into one frame: 13008 → 12896 B.

None of them used an allowlist entry, and each measured against a baseline it built
itself rather than trusting a number from a report.

**Why this must not sit.** The verifier work is a security surface — it decides which
programs may load. Shipping it on a call path that can overrun the kernel stack couples
a correctness win to a memory-corruption risk, and the corruption presents as an
unrelated victim at a random later time, which is the hardest possible thing to
attribute back to here.

Next lane should build the aarch64 kernel, take its own `make stack-gate` baseline,
identify this branch's delta, and split the offending frame. See the
"Verification must be able to fail" and stack-guard notes in CLAUDE.md.
