# B1857 — IRQ/softirq scheduling fault

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | INFRA | med | The `nscg` hosted tests share install-once namespace callbacks, so a full workspace test run is red even though the package's 55 other tests pass. The two failing tests each unwrap `AlreadyInstalled`, making their result depend on process-global installation order. | Reproduced unchanged on `main` at `c96b8025e` with `cargo test -p nscg --lib`: 55 passed, 2 failed (`capability_walk_uses_concrete_user_parent_owners`, `network_proc_link_retains_exact_owner_after_task_exit`), both on `AlreadyInstalled`. | unowned |
