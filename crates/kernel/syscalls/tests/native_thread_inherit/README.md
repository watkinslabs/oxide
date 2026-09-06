# Native-thread desktop inheritance boundary

Standalone hosted workspace. Build script loads the production lifecycle imports
and complete `prepare` function verbatim. Real scheduler Task/registry/native
creation state, process-default desktop, VMM and TEB builder are linked. Usercopy
and current-runqueue initialization are hosted boundaries; the latter asserts
desktop inheritance before runtime initialization.

```sh
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/control-id-20260906/cargo-target cargo test --offline --manifest-path crates/kernel/syscalls/tests/native_thread_inherit/Cargo.toml --lib -- --test-threads=1
REMOVE_INHERIT_HOOK=1 CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/control-id-20260906/cargo-target cargo test --offline --manifest-path crates/kernel/syscalls/tests/native_thread_inherit/Cargo.toml --lib tests::actual_prepare_inherits_process_default_before_runtime_initialization -- --exact
```

First command must pass both tests. Second must fail the selected test at
runtime initialization with missing inherited desktop. Mutation removes exactly
one hook from the generated OUT_DIR copy, never production source. Unset
`REMOVE_INHERIT_HOOK` and repeat the first command to restore/verify green.

Frozen contract: 31fl §6.
The creator selects a different desktop from the process default. The second
test faults output and checks real mapping rollback and no attachment/publication.
No desktop issuance, session authority, root construction or boot is exercised.
