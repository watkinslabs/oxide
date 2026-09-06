# AF_UNIX resolver permission boundary

Standalone hosted workspace loading the actual canonical resolver body.
Production VFS inode permission, Unix address construction, Landlock boundary
and errno mappings remain linked. Only path lookup and current credentials are
injected. This verifies final-inode DAC and ordering, not mount/network namespace
selection or a live connection. Contract: 24 §9.

Run with a private disk target:

```sh
CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/desktop-authority cargo test --offline --manifest-path crates/kernel/syscalls/tests/unix_resolver_permission/Cargo.toml --lib
REMOVE_UNIX_DAC_HOOK=1 CARGO_TARGET_DIR=/home/nd/oxide/kernel/target/codex-lanes/desktop-authority cargo test --offline --manifest-path crates/kernel/syscalls/tests/unix_resolver_permission/Cargo.toml --lib tests::nonwritable_nonsocket_denied_before_type_check -- --exact
```

The second command must fail: removing only the generated permission hook
changes EACCES to ECONNREFUSED. Production files are never modified. Unset the
mutation variable and repeat the first command to restore and verify green.
