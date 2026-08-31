# Windows native NT mutants

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`31h`,`52`,`53`. Provides: thread-owned recursive mutex objects for the NT personality.

## 1 Contract

- `NtCreateMutant` creates an unnamed process-local mutant and may assign initial ownership to the creating NT thread.
- A mutant is signaled when unowned; its owner may reacquire it recursively.
- `NtReleaseMutant` accepts only the owning thread, returns the previous negative recursion count, and wakes waiters on final release.
- `NtQueryMutant` class `MutantBasicInformation` returns the 8-byte current-count/ownership/abandoned view and requires the exact output length.
- Mutants participate in single and multiple waits through the scheduler wait predicate; Linux futex and event paths remain separate.
- Named-object namespaces and abandoned-owner teardown remain separate follow-up contracts; unnamed correctness comes first for the initial Wine runtime.

## 2 Tests

- recursive acquisition and final-release count follow the NT mutant contract;
- non-owner release fails without changing ownership; query reports each recursive level;
- mutant handles enforce modify-state access and reject wrong object types;
- single and multiple waits treat an owned-by-caller mutant as immediately acquirable;
- x86-64 service selectors remain append-only and aarch64 kernel checks remain green.
